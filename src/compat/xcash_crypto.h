#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <utility>

#include "crypto/crypto.h"

namespace lws
{
namespace compat
{
namespace detail
{
  struct fallback_random_device
  {
    using result_type = std::uint64_t;

    static constexpr result_type min() noexcept
    {
      return std::numeric_limits<result_type>::min();
    }

    static constexpr result_type max() noexcept
    {
      return std::numeric_limits<std::uint64_t>::max();
    }

    result_type operator()() const
    {
      return ::crypto::rand<result_type>();
    }
  };

  inline std::uint64_t fallback_rand_idx(std::uint64_t bound)
  {
    if (bound == 0)
      return 0;

    const auto limit = std::numeric_limits<std::uint64_t>::max() -
      (std::numeric_limits<std::uint64_t>::max() % bound);

    std::uint64_t value = 0;
    do
    {
      value = ::crypto::rand<std::uint64_t>();
    } while (value >= limit);

    return value % bound;
  }
} // namespace detail

using random_device = detail::fallback_random_device;

inline std::uint64_t rand_idx(std::uint64_t bound)
{
  return detail::fallback_rand_idx(bound);
}

inline bool generate_key_derivation(
  const ::crypto::public_key& pub,
  const ::crypto::secret_key& sec,
  ::crypto::key_derivation& derivation)
{
  return ::crypto::generate_key_derivation(pub, sec, derivation);
}

inline bool derive_subaddress_public_key(
  const ::crypto::public_key& out_key,
  const ::crypto::key_derivation& derivation,
  std::size_t output_index,
  ::crypto::public_key& derived)
{
  return ::crypto::derive_subaddress_public_key(out_key, derivation, output_index, derived);
}
} // namespace compat
} // namespace lws
