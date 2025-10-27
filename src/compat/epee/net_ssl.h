// Copyright (c) 2006-2013, Andrey N. Sabelnikov
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

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/system/error_code.hpp>
#include <boost/utility/string_ref.hpp>

#define SSL_FINGERPRINT_SIZE 32

namespace epee
{
namespace net_utils
{
  enum class ssl_support_t : std::uint8_t
  {
    e_ssl_support_disabled,
    e_ssl_support_enabled,
    e_ssl_support_autodetect,
  };

  enum class ssl_verification_t : std::uint8_t
  {
    none = 0,
    system_ca,
    user_certificates,
    user_ca
  };

  struct ssl_authentication_t
  {
    std::string private_key_path;
    std::string certificate_path;

    void use_ssl_certificate(boost::asio::ssl::context& ssl_context) const;
  };

  class ssl_options_t
  {
    std::vector<std::vector<std::uint8_t>> fingerprints_;

  public:
    std::string ca_path;
    ssl_authentication_t auth;
    ssl_support_t support;
    ssl_verification_t verification;

    ssl_options_t(ssl_support_t support);
    ssl_options_t(std::vector<std::vector<std::uint8_t>> fingerprints, std::string ca_path);

    ssl_options_t(const ssl_options_t&) = default;
    ssl_options_t(ssl_options_t&&) = default;
    ssl_options_t& operator=(const ssl_options_t&) = default;
    ssl_options_t& operator=(ssl_options_t&&) = default;

    explicit operator bool() const noexcept { return support != ssl_support_t::e_ssl_support_disabled; }

    bool has_strong_verification(boost::string_ref host) const noexcept;
    bool has_fingerprint(boost::asio::ssl::verify_context& ctx) const;

    void configure(
      boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket,
      boost::asio::ssl::stream_base::handshake_type type,
      const std::string& host = {}) const;
    boost::asio::ssl::context create_context() const;

    bool handshake(
      boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket,
      boost::asio::ssl::stream_base::handshake_type type,
      boost::asio::const_buffer buffer = {},
      const std::string& host = {},
      std::chrono::milliseconds timeout = std::chrono::seconds(15)) const;
  };

  constexpr std::size_t get_ssl_magic_size() { return 9; }
  bool is_ssl(const unsigned char* data, std::size_t len);
  bool ssl_support_from_string(ssl_support_t& ssl, boost::string_ref s);

  bool create_ec_ssl_certificate(EVP_PKEY*& pkey, X509*& cert);
  bool create_rsa_ssl_certificate(EVP_PKEY*& pkey, X509*& cert);

  boost::system::error_code store_ssl_keys(boost::asio::ssl::context& ssl, const boost::filesystem::path& base);
} // namespace net_utils
} // namespace epee
