#pragma once

#include "cryptonote_config.h"

namespace config
{
#ifndef HASH_KEY_SUBADDRESS
inline constexpr char HASH_KEY_SUBADDRESS[] = "SubAddr";
#endif

#ifndef HASH_KEY_ENCRYPTED_PAYMENT_ID
inline constexpr unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
#endif
} // namespace config

#define LWS_SUPPORTS_OUTPUT_DISTRIBUTION 0

namespace lws
{
namespace compat
{
inline constexpr bool supports_output_distribution = (LWS_SUPPORTS_OUTPUT_DISTRIBUTION != 0);
} // namespace compat
} // namespace lws
