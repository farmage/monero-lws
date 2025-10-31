#pragma once

#include <optional>
#include <cstdint>

#include "db/storage.h"
#include "rpc/client.h"
#include "rpc/daemon_zmq.h"

namespace lws
{
namespace block_cache
{
  //! Load cached response for `start_height`. \return std::nullopt if not cached.
  expect<std::optional<rpc::get_blocks_fast_response>>
    load(db::storage& disk, std::uint64_t start_height);

  //! Persist daemon response for `start_height`.
  expect<void>
    store(db::storage& disk, std::uint64_t start_height, const rpc::get_blocks_fast_response& response);

  struct warm_result
  {
    std::uint64_t cached_from;
    std::uint64_t cached_to;
    std::size_t batches;
  };

  //! Sequentially download blocks starting at `start_height` and populate the cache.
  expect<warm_result>
    warm(db::storage& disk, rpc::client client, std::uint64_t start_height, std::optional<std::uint64_t> stop_height = std::nullopt);

  //! Compare cached data against daemon responses over a range of blocks.
  expect<void>
    verify(db::storage& disk, rpc::client client, std::uint64_t start_height, std::size_t block_count);
} // namespace block_cache
} // namespace lws
