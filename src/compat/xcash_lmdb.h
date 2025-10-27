#pragma once

// Collects the LMDB compatibility wrappers that mirror the modern Monero
// interfaces while staying within the local tree (the xcash core bundle
// does not provide these helpers).

#include "compat/lmdb/database.h"
#include "compat/lmdb/error.h"
#include "compat/lmdb/key_stream.h"
#include "compat/lmdb/table.h"
#include "compat/lmdb/transaction.h"
#include "compat/lmdb/util.h"
#include "compat/lmdb/value_stream.h"
