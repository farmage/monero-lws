#pragma once

#include <cstdint>

#include "ringct/rctOps.h"

namespace lws
{
namespace compat
{
inline void ecdh_decode(::rct::ecdhTuple& tuple, const ::rct::key& shared_sec, bool bulletproof2)
{
  (void)bulletproof2;
  ::rct::ecdhDecode(tuple, shared_sec);
}

inline void ecdh_encode(::rct::ecdhTuple& tuple, const ::rct::key& shared_sec, bool bulletproof2)
{
  (void)bulletproof2;
  ::rct::ecdhEncode(tuple, shared_sec);
}

inline bool is_bulletproof_v2(std::uint8_t type) noexcept
{
  (void)type;
  return false;
}
} // namespace compat
} // namespace lws
