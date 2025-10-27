// Copyright (c) 2018-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <algorithm>
#include <boost/asio/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/cerrno.hpp>
#include <boost/filesystem/operations.hpp>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mutex>
#include <stdexcept>
#include <thread>

#include "file_io_utils.h"
#include "misc_log_ex.h"
#include "net/net_helper.h"
#include "compat/epee/net_ssl.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.ssl"

#ifdef _WIN32
#include <wincrypt.h>
static void add_windows_root_certs(SSL_CTX* ctx) noexcept;
#endif

namespace
{
  struct openssl_bio_free
  {
    void operator()(BIO* ptr) const noexcept
    {
      BIO_free(ptr);
    }
  };
  using openssl_bio = std::unique_ptr<BIO, openssl_bio_free>;

  struct openssl_pkey_free
  {
    void operator()(EVP_PKEY* ptr) const noexcept
    {
      EVP_PKEY_free(ptr);
    }
  };
  using openssl_pkey = std::unique_ptr<EVP_PKEY, openssl_pkey_free>;

  struct openssl_rsa_free
  {
    void operator()(RSA* ptr) const noexcept
    {
      RSA_free(ptr);
    }
  };
  using openssl_rsa = std::unique_ptr<RSA, openssl_rsa_free>;

  struct openssl_bignum_free
  {
    void operator()(BIGNUM* ptr) const noexcept
    {
      BN_free(ptr);
    }
  };
  using openssl_bignum = std::unique_ptr<BIGNUM, openssl_bignum_free>;

  struct openssl_ec_key_free
  {
    void operator()(EC_KEY* ptr) const noexcept
    {
      EC_KEY_free(ptr);
    }
  };
  using openssl_ec_key = std::unique_ptr<EC_KEY, openssl_ec_key_free>;

  struct openssl_group_free
  {
    void operator()(EC_GROUP* ptr) const noexcept
    {
      EC_GROUP_free(ptr);
    }
  };
  using openssl_group = std::unique_ptr<EC_GROUP, openssl_group_free>;

  boost::system::error_code load_ca_file(boost::asio::ssl::context& ctx, const std::string& path)
  {
    SSL_CTX* const ssl_ctx = ctx.native_handle();
    if (ssl_ctx == nullptr)
      return {boost::asio::error::invalid_argument};

    if (!SSL_CTX_load_verify_locations(ssl_ctx, path.c_str(), nullptr))
    {
      return {int(::ERR_get_error()), boost::asio::error::get_ssl_category()};
    }
    return {};
  }
}

namespace epee
{
namespace net_utils
{
ssl_options_t::ssl_options_t(const ssl_support_t support)
  : fingerprints_(),
    ca_path(),
    auth(),
    support(support),
    verification(support == ssl_support_t::e_ssl_support_disabled ? ssl_verification_t::none : ssl_verification_t::system_ca)
{}

ssl_options_t::ssl_options_t(std::vector<std::vector<std::uint8_t>> fingerprints, std::string ca_path)
  : fingerprints_(std::move(fingerprints)),
    ca_path(std::move(ca_path)),
    auth(),
    support(ssl_support_t::e_ssl_support_enabled),
    verification(ssl_verification_t::user_certificates)
{
  for (const std::vector<std::uint8_t>& fingerprint : fingerprints_)
  {
    if (fingerprint.size() != SSL_FINGERPRINT_SIZE)
      throw std::invalid_argument{"Invalid SSL fingerprint length"};
  }
}

bool ssl_options_t::has_strong_verification(const boost::string_ref host) const noexcept
{
  switch (verification)
  {
  case ssl_verification_t::none:
    return false;
  case ssl_verification_t::system_ca:
    return 0 < host.size();
  case ssl_verification_t::user_ca:
    return !ca_path.empty();
  case ssl_verification_t::user_certificates:
    return !fingerprints_.empty();
  }
  return false;
}

bool ssl_options_t::has_fingerprint(boost::asio::ssl::verify_context& ctx) const
{
  if (fingerprints_.empty())
    return false;

  X509_STORE_CTX* store_ctx = ctx.native_handle();
  if (!store_ctx)
    return false;

  X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
  if (!cert)
    return false;

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int size = 0;
  if (!X509_digest(cert, EVP_sha256(), digest, &size))
    return false;
  if (size != SSL_FINGERPRINT_SIZE)
    return false;

  return std::any_of(
    fingerprints_.begin(), fingerprints_.end(),
    [&digest] (const std::vector<std::uint8_t>& fingerprint) {
      return std::equal(fingerprint.begin(), fingerprint.end(), digest);
    });
}

namespace
{
  bool load_root_certificates(boost::asio::ssl::context& ctx, const std::string& path)
  {
    if (boost::system::error_code err = load_ca_file(ctx, path))
    {
      MERROR("Failed to load root certificates at \"" << path << "\": " << err.message());
      return false;
    }
    return true;
  }
}

boost::asio::ssl::context ssl_options_t::create_context() const
{
  boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12};

  const auto configure_certs = [this, &ctx] () {
    if (!auth.private_key_path.empty() && !auth.certificate_path.empty())
      auth.use_ssl_certificate(ctx);

    switch (verification)
    {
    case ssl_verification_t::system_ca:
#ifdef _WIN32
      add_windows_root_certs(ctx.native_handle());
#endif
      break;
    case ssl_verification_t::user_certificates:
    case ssl_verification_t::user_ca:
      if (ca_path.empty())
        throw std::invalid_argument{"user CA path missing"};
      load_root_certificates(ctx, ca_path);
      break;
    case ssl_verification_t::none:
      break;
    }
  };

  configure_certs();
  ctx.set_default_verify_paths();
  return ctx;
}

void ssl_authentication_t::use_ssl_certificate(boost::asio::ssl::context& ssl_context) const
{
  namespace bf = boost::filesystem;
  if (certificate_path.empty())
    throw std::invalid_argument{"certificate path missing"};
  if (!bf::exists(certificate_path))
    throw std::invalid_argument{"certificate path does not exist"};

  if (private_key_path.empty())
    throw std::invalid_argument{"private key path missing"};
  if (!bf::exists(private_key_path))
    throw std::invalid_argument{"private key path does not exist"};

  ssl_context.use_certificate_file(certificate_path, boost::asio::ssl::context::pem);
  ssl_context.use_private_key_file(private_key_path, boost::asio::ssl::context::pem);
}

void ssl_options_t::configure(
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket,
  boost::asio::ssl::stream_base::handshake_type type,
  const std::string& host) const
{
  socket.set_verify_mode(boost::asio::ssl::verify_none);

  if (!has_strong_verification(host))
    return;

  const auto verify_fun = [this, host] (const bool preverified, boost::asio::ssl::verify_context& ctx) -> bool
  {
    if (preverified && verification != ssl_verification_t::user_certificates)
      return true;
    if (has_fingerprint(ctx))
      return true;

    if (verification == ssl_verification_t::system_ca && !host.empty())
      return boost::asio::ssl::rfc2818_verification(host)(preverified, ctx);
    return false;
  };

  try
  {
    if (!fingerprints_.empty())
      socket.set_verify_mode(boost::asio::ssl::verify_peer);

    socket.set_verify_callback(verify_fun);
  }
  catch (const boost::system::system_error& e)
  {
    MERROR("Failed to set verify callback: " << e.code().message());
  }
}

bool ssl_options_t::handshake(
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket,
  boost::asio::ssl::stream_base::handshake_type type,
  const boost::asio::const_buffer buffer,
  const std::string& host,
  const std::chrono::milliseconds timeout) const
{
  if (!*this)
    return false;

  const auto worker = [this, &socket, type, buffer, &host] ()
  {
    configure(socket, type, host);
    if (buffer.size())
      socket.next_layer().send(boost::asio::buffer(buffer));
    socket.handshake(type);
  };

  std::exception_ptr error;
  std::mutex mutex;
  std::condition_variable cv;
  bool completed = false;

  auto& ctx = static_cast<boost::asio::io_context&>(socket.get_executor().context());
  boost::asio::io_context::strand strand{ctx};
  ctx.post(strand.wrap([&] {
    try
    {
      worker();
    }
    catch (...)
    {
      error = std::current_exception();
    }

    {
      std::lock_guard<std::mutex> lock{mutex};
      completed = true;
    }
    cv.notify_one();
  }));

  std::unique_lock<std::mutex> lock{mutex};
  cv.wait_for(lock, timeout, [&completed](){ return completed; });

  if (!completed)
  {
    ctx.post(strand.wrap([&socket] {
      boost::system::error_code ignored;
      socket.lowest_layer().cancel(ignored);
    }));
    return false;
  }

  if (error)
  {
    std::rethrow_exception(error);
  }
  return true;
}

bool ssl_support_from_string(ssl_support_t& ssl, const boost::string_ref s)
{
  const std::string value{s.begin(), s.end()};
  if (value == "enabled")
  {
    ssl = ssl_support_t::e_ssl_support_enabled;
    return true;
  }
  if (value == "disabled")
  {
    ssl = ssl_support_t::e_ssl_support_disabled;
    return true;
  }
  if (value == "autodetect")
  {
    ssl = ssl_support_t::e_ssl_support_autodetect;
    return true;
  }
  return false;
}

bool is_ssl(const unsigned char* data, const std::size_t len)
{
  if (len < get_ssl_magic_size())
    return false;

  constexpr unsigned char ssl_magic[] = {0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  return std::equal(std::begin(ssl_magic), std::end(ssl_magic), data, data + get_ssl_magic_size());
}

bool create_rsa_ssl_certificate(EVP_PKEY*& pkey, X509*& cert)
{
  MINFO("Generating SSL certificate");
  pkey = EVP_PKEY_new();
  if (!pkey)
  {
    MERROR("Failed to create new private key");
    return false;
  }

  openssl_pkey pkey_deleter{pkey};
  openssl_rsa rsa{RSA_new()};
  if (!rsa)
  {
    MERROR("Error allocating RSA private key");
    return false;
  }

  openssl_bignum exponent{BN_new()};
  if (!exponent)
  {
    MERROR("Error allocating exponent");
    return false;
  }

  BN_set_word(exponent.get(), RSA_F4);

  if (RSA_generate_key_ex(rsa.get(), 4096, exponent.get(), nullptr) != 1)
  {
    MERROR("Error generating RSA private key");
    return false;
  }

  if (EVP_PKEY_assign_RSA(pkey, rsa.get()) <= 0)
  {
    MERROR("Error assigning RSA private key");
    return false;
  }
  (void)rsa.release();

  cert = X509_new();
  if (!cert)
  {
    MERROR("Failed to create new X509 certificate");
    return false;
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 182);
  if (!X509_set_pubkey(cert, pkey))
  {
    MERROR("Error setting pubkey on certificate");
    X509_free(cert);
    return false;
  }
  X509_NAME* name = X509_get_subject_name(cert);
  X509_set_issuer_name(cert, name);

  if (X509_sign(cert, pkey, EVP_sha256()) == 0)
  {
    MERROR("Error signing certificate");
    X509_free(cert);
    return false;
  }

  pkey_deleter.release();
  return true;
}

bool create_ec_ssl_certificate(EVP_PKEY*& pkey, X509*& cert)
{
  MINFO("Generating SSL certificate");
  pkey = EVP_PKEY_new();
  if (!pkey)
  {
    MERROR("Failed to create new private key");
    return false;
  }

  openssl_pkey pkey_deleter{pkey};
  openssl_ec_key ec{EC_KEY_new()};
  if (!ec)
  {
    MERROR("Error allocating EC key");
    return false;
  }

  openssl_group group{EC_GROUP_new_by_curve_name(NID_secp384r1)};
  if (!group)
  {
    MERROR("Error allocating EC group");
    return false;
  }

  if (EC_KEY_set_group(ec.get(), group.get()) != 1)
  {
    MERROR("Error setting EC group");
    return false;
  }

  if (EC_KEY_generate_key(ec.get()) != 1)
  {
    MERROR("Error generating EC private key");
    return false;
  }

  if (EVP_PKEY_assign_EC_KEY(pkey, ec.get()) <= 0)
  {
    MERROR("Error assigning EC private key");
    return false;
  }
  (void)ec.release();

  cert = X509_new();
  if (!cert)
  {
    MERROR("Failed to create new X509 certificate");
    return false;
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 182);
  if (!X509_set_pubkey(cert, pkey))
  {
    MERROR("Error setting pubkey on certificate");
    X509_free(cert);
    return false;
  }
  X509_NAME* name = X509_get_subject_name(cert);
  X509_set_issuer_name(cert, name);

  if (X509_sign(cert, pkey, EVP_sha384()) == 0)
  {
    MERROR("Error signing certificate");
    X509_free(cert);
    return false;
  }

  pkey_deleter.release();
  return true;
}

boost::system::error_code store_ssl_keys(boost::asio::ssl::context& ssl, const boost::filesystem::path& base)
{
  boost::filesystem::path key_file = base;
  key_file += ".key";
  boost::filesystem::path cert_file = base;
  cert_file += ".crt";
  boost::system::error_code ec;

  BIO* out = BIO_new_file(key_file.string().c_str(), "w");
  if (!out)
  {
    return {int(ERR_get_error()), boost::asio::error::get_ssl_category()};
  }

  EVP_PKEY* key = nullptr;
  X509* cert = nullptr;

  if (!create_ec_ssl_certificate(key, cert))
  {
    if (cert == nullptr)
      create_rsa_ssl_certificate(key, cert);
  }

  if (!key || !cert)
  {
    BIO_free(out);
    return {int(ERR_get_error()), boost::asio::error::get_ssl_category()};
  }

  PEM_write_bio_PrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr);
  BIO_free(out);

  out = BIO_new_file(cert_file.string().c_str(), "w");
  if (!out)
  {
    EVP_PKEY_free(key);
    X509_free(cert);
    return {int(ERR_get_error()), boost::asio::error::get_ssl_category()};
  }
  PEM_write_bio_X509(out, cert);
  BIO_free(out);

  ssl.use_private_key_file(key_file.string(), boost::asio::ssl::context::pem);
  ssl.use_certificate_file(cert_file.string(), boost::asio::ssl::context::pem);
  EVP_PKEY_free(key);
  X509_free(cert);

  return ec;
}

#ifdef _WIN32
void add_windows_root_certs(SSL_CTX* ctx) noexcept
{
  HCERTSTORE system_store = CertOpenSystemStore(0, L"ROOT");
  if (!system_store)
    return;

  X509_STORE* store = SSL_CTX_get_cert_store(ctx);
  if (!store)
  {
    CertCloseStore(system_store, 0);
    return;
  }

  PCCERT_CONTEXT cert_context = nullptr;
  while ((cert_context = CertEnumCertificatesInStore(system_store, cert_context)) != nullptr)
  {
    const unsigned char* encoded_cert = cert_context->pbCertEncoded;
    X509* x509 = d2i_X509(nullptr, &encoded_cert, cert_context->cbCertEncoded);
    if (x509)
    {
      X509_STORE_add_cert(store, x509);
      X509_free(x509);
    }
  }

  CertCloseStore(system_store, 0);
}
#endif
} // namespace net_utils
} // namespace epee
