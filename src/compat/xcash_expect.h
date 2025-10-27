#pragma once

// Pull in the X-Cash expect helpers and map the Monero helper macros to the
// older names exposed by X-Cash. This keeps the upstream LWS sources building
// without modification while the core remains untouched.

#include "common/expect.h"
#include "compat/hex.h"

#ifndef MONERO_PRECOND
#define MONERO_PRECOND(...) XCASH_PRECOND(__VA_ARGS__)
#endif

#ifndef MONERO_CHECK
#define MONERO_CHECK(...) XCASH_CHECK(__VA_ARGS__)
#endif

#ifndef MONERO_UNWRAP
#define MONERO_UNWRAP(...) XCASH_UNWRAP(__VA_ARGS__)
#endif

#ifndef MONERO_THROW
#define MONERO_THROW(...) XCASH_THROW(__VA_ARGS__)
#endif
