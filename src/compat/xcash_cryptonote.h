#pragma once

#include <type_traits>

#include <boost/optional/optional.hpp>
#include <boost/variant/get.hpp>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace lws
{
namespace compat
{
inline constexpr bool supports_view_tags = false;

inline bool view_tag_matches(
  const cryptonote::tx_out& out,
  const crypto::key_derivation& derivation,
  std::size_t index)
{
  (void)out;
  (void)derivation;
  (void)index;
  return true;
}

inline bool get_output_public_key(const cryptonote::tx_out& out, crypto::public_key& key)
{
  if (const auto* to_key = boost::get<cryptonote::txout_to_key>(&out.target))
  {
    key = to_key->key;
    return true;
  }
  return false;
}
} // namespace compat
} // namespace lws
