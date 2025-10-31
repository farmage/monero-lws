#include "block_cache.h"

#include "common/expect.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "error.h"
#include "misc_log_ex.h"
#include "rpc/json.h"
#include "rpc/message_data_structs.h"
#include "rpc/daemon_messages.h"
#include "string_tools.h"

#include <unordered_map>
#include <chrono>
#include <limits>
#include <system_error>

namespace lws
{
namespace block_cache
{
  namespace
  {
    struct block_summary
    {
      std::uint64_t height;
      crypto::hash hash;
    };

    expect<std::vector<block_summary>> summarize_response(const rpc::get_blocks_fast_response& response, std::uint64_t min_height, std::uint64_t max_height)
    {
      std::vector<block_summary> out{};
      out.reserve(response.blocks.size());

      for (std::size_t i = 0; i < response.blocks.size(); ++i)
      {
        std::uint64_t height = 0;
        if (response.start_height != 0 && response.start_height != 1)
        {
          if (i == 0)
            height = response.start_height - 1;
          else
            height = response.start_height + i - 1;
        }
        else
          height = response.start_height + i;

        if (height < min_height)
          continue;
        if (max_height < height)
          continue;

        crypto::hash hash{};
        if (!cryptonote::get_block_hash(response.blocks[i].block, hash))
          return {lws::error::bad_blockchain};
        out.push_back(block_summary{height, hash});
      }
      return out;
    }

    expect<db::block_cache_value> make_value(const rpc::get_blocks_fast_response& response)
    {
      db::block_cache_value value{};
      value.current_height = response.current_height;
      if (response.blocks.size() != response.output_indices.size())
        return {error::bad_daemon_response};

      value.blocks.reserve(response.blocks.size());
      for (std::size_t i = 0; i < response.blocks.size(); ++i)
      {
        db::block_cache_block cached{};
        cached.output_indices = response.output_indices[i];
        try
        {
          cached.block_blob = cryptonote::block_to_blob(response.blocks[i].block);
        }
        catch (const std::exception& e)
        {
          MERROR("Failed to serialize block for cache: " << e.what());
          return {common_error::kInvalidArgument};
        }

        cached.tx_blobs.reserve(response.blocks[i].transactions.size());
        for (const auto& tx : response.blocks[i].transactions)
        {
          try
          {
            cached.tx_blobs.push_back(cryptonote::tx_to_blob(tx));
          }
          catch (const std::exception& e)
          {
            MERROR("Failed to serialize transaction for cache: " << e.what());
            return {common_error::kInvalidArgument};
          }
        }

        value.blocks.push_back(std::move(cached));
      }

      return value;
    }

    expect<std::optional<rpc::get_blocks_fast_response>>
    from_value(db::storage& disk, std::uint64_t start_height, db::block_cache_value value)
    {
      rpc::get_blocks_fast_response response{};
      response.start_height = start_height;
      response.current_height = value.current_height;
      response.blocks.resize(value.blocks.size());
      response.output_indices.resize(value.blocks.size());

      for (std::size_t i = 0; i < value.blocks.size(); ++i)
      {
        const auto& cached = value.blocks[i];

        cryptonote::block block{};
        if (!cryptonote::parse_and_validate_block_from_blob(cached.block_blob, block))
        {
          MWARNING("Invalid block cache entry at height " << start_height << ", dropping");
          MONERO_CHECK(disk.erase_block_cache(db::block_id(start_height)));
          return std::optional<rpc::get_blocks_fast_response>{};
        }

        response.blocks[i].block = std::move(block);
        response.blocks[i].transactions.reserve(cached.tx_blobs.size());
        for (const auto& tx_blob : cached.tx_blobs)
        {
          cryptonote::transaction tx{};
          if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx))
          {
            MWARNING("Invalid transaction in block cache at height " << start_height << ", dropping");
            MONERO_CHECK(disk.erase_block_cache(db::block_id(start_height)));
            return std::optional<rpc::get_blocks_fast_response>{};
          }
          response.blocks[i].transactions.push_back(std::move(tx));
        }

        response.output_indices[i] = cached.output_indices;
      }

      return std::optional<rpc::get_blocks_fast_response>{std::move(response)};
    }
  } // anonymous namespace

  expect<std::optional<rpc::get_blocks_fast_response>>
  load(db::storage& disk, std::uint64_t start_height)
  {
    auto reader = disk.start_read();
    if (!reader)
      return reader.error();

    auto cached = reader->get_block_cache_span(db::block_id(start_height));
    if (!cached)
    {
      const std::error_code ec = cached.error();
      reader->finish_read();
      MWARNING("Dropping block cache entry at height " << start_height << ": " << ec.message());
      auto removed = disk.erase_block_cache(db::block_id(start_height));
      if (!removed)
        MWARNING("Failed to erase block cache entry at height " << start_height << ": " << removed.error().message());
      return std::optional<rpc::get_blocks_fast_response>{};
    }

    reader->finish_read();

    if (!*cached)
      return std::optional<rpc::get_blocks_fast_response>{};

    auto pair = std::move(**cached);
    const std::uint64_t entry_start = std::uint64_t(pair.first);
    if (entry_start > start_height)
      return std::optional<rpc::get_blocks_fast_response>{};

    auto response = from_value(disk, entry_start, std::move(pair.second));
    if (!response)
      return response.error();

    if (!*response)
      return std::optional<rpc::get_blocks_fast_response>{};

    rpc::get_blocks_fast_response resp = std::move(**response);
    if (entry_start != start_height)
      return std::optional<rpc::get_blocks_fast_response>{};

    return std::optional<rpc::get_blocks_fast_response>{std::move(resp)};
  }

  expect<void> store(db::storage& disk, std::uint64_t start_height, const rpc::get_blocks_fast_response& response)
  {
    auto value = make_value(response);
    if (!value)
      return value.error();
    return disk.store_block_cache(db::block_id(start_height), *value);
  }

  expect<warm_result> warm(db::storage& disk, rpc::client client, std::uint64_t start_height, std::optional<std::uint64_t> stop_height)
  {
    if (!client)
      return {common_error::kInvalidArgument};

    constexpr std::chrono::seconds send_timeout{30};
    constexpr std::chrono::seconds receive_timeout{120};

    warm_result result{};
    result.cached_from = 0;
    result.cached_to = 0;
    result.batches = 0;

    std::uint64_t next_height = start_height ? start_height : 1;
    const std::uint64_t target = stop_height.value_or(std::numeric_limits<std::uint64_t>::max());

    if (stop_height)
      MINFO("Starting block cache warm-up from height " << next_height << " to " << *stop_height);
    else
      MINFO("Starting block cache warm-up from height " << next_height << " to chain tip");

    auto log_range = [&](const char* action, std::uint64_t response_start, std::uint64_t last_height, std::size_t batches, std::uint64_t current_height)
    {
      std::uint64_t goal = target;
      if (goal == std::numeric_limits<std::uint64_t>::max() && current_height)
        goal = current_height - (current_height ? 1 : 0);

      std::uint64_t base = result.cached_from ? result.cached_from : response_start;
      std::uint64_t numerator = 0;
      if (last_height >= base)
        numerator = last_height - base + 1;

      std::uint64_t denominator = 0;
      if (goal != std::numeric_limits<std::uint64_t>::max() && goal >= base)
        denominator = goal - base + 1;

      std::uint64_t percent = 0;
      if (denominator)
      {
        if (numerator >= denominator)
          percent = 100;
        else
          percent = (numerator * 100) / denominator;
      }

      if (denominator)
        MINFO("Warm-up " << action << " " << response_start << " -> " << last_height << " (" << batches << " batch(es), " << percent << "%)");
      else
        MINFO("Warm-up " << action << " " << response_start << " -> " << last_height << " (" << batches << " batch(es))");
    };

    while (next_height <= target)
    {
      auto cached_entry = load(disk, next_height);
      if (!cached_entry)
        return cached_entry.error();

      if (*cached_entry)
      {
        const auto& cached_resp = **cached_entry;
        if (!cached_resp.blocks.empty())
        {
          const std::uint64_t response_start = cached_resp.start_height;
          const std::uint64_t last_height = response_start + cached_resp.blocks.size() - 1;

          if (result.cached_from == 0)
            result.cached_from = response_start;
          result.cached_to = last_height;

          log_range("skipping cached blocks", response_start, last_height, result.batches, cached_resp.current_height);

         if (last_height >= target)
           break;

          // next_height = last_height + 1;
            std::uint64_t next_rounded_down = ((last_height / 1000) +1) * 1000;
            if (next_height == next_rounded_down)
              MWARNING("Already at target boundary for height " << next_height);
            next_height = next_rounded_down;
          continue;
        }
      }

      cryptonote::rpc::GetBlocksFast::Request req{};
      req.start_height = next_height;
      req.prune = false;

      auto message = rpc::client::make_message("get_blocks_fast", req);
      MONERO_CHECK(client.send(std::move(message), send_timeout));

      auto response = client.get_message(receive_timeout);
      if (!response)
        return response.error();

      auto parsed = rpc::parse_json_response<rpc::get_blocks_fast>(std::move(*response));
      if (!parsed)
        return parsed.error();

      if (parsed->blocks.empty())
        break;

      const std::uint64_t response_start = parsed->start_height;
      MONERO_CHECK(store(disk, response_start, *parsed));

      ++result.batches;
      if (result.cached_from == 0)
        result.cached_from = response_start;

      std::uint64_t last_height = response_start;
      if (!parsed->blocks.empty())
        last_height = response_start + parsed->blocks.size() - 1;
      result.cached_to = last_height;

      log_range("cached blocks", response_start, last_height, result.batches, parsed->current_height);

      if (last_height >= target)
        break;

      if (parsed->blocks.size() <= 1)
        break;

      if (parsed->current_height <= last_height)
        break;

      const std::uint64_t batch_size = static_cast<std::uint64_t>(parsed->blocks.size());
      if (batch_size < 1000) {
        MWARNING("Small batch size detected: " << batch_size << " blocks. This may indicate inefficient caching.");
      }

      std::uint64_t next_rounded_down = ((last_height / 1000) +1) * 1000;
      next_height = next_rounded_down;

      // if (response_start <= 1)
      //   next_height = response_start + batch_size - 1;
      // else
      //   next_height = response_start + batch_size;
    }

    if (result.batches)
      MINFO("Finished block cache warm-up: " << result.cached_from << " -> " << result.cached_to << " in " << result.batches << " batch(es)");
    else
      MINFO("Block cache warm-up complete - no new batches cached");

    return result;
  }

  expect<void> verify(db::storage& disk, rpc::client client, std::uint64_t start_height, std::size_t block_count)
  {
    if (!client)
      return {common_error::kInvalidArgument};
    if (block_count == 0)
      return success();

    constexpr std::chrono::seconds send_timeout{30};
    constexpr std::chrono::seconds receive_timeout{120};

    std::uint64_t next_height = start_height;
    if (next_height == 0)
      next_height = 1;

    std::uint64_t target_height = std::numeric_limits<std::uint64_t>::max();
    if (block_count != std::numeric_limits<std::size_t>::max())
    {
      const std::uint64_t span = block_count - 1;
      if (next_height <= std::numeric_limits<std::uint64_t>::max() - span)
        target_height = next_height + span;
    }

    std::size_t remaining = block_count;
    bool all_match = true;

    MINFO("Verifying block cache from height " << next_height << " to " << (target_height == std::numeric_limits<std::uint64_t>::max() ? std::numeric_limits<std::uint64_t>::max() : target_height));

    while (remaining && next_height <= target_height)
    {
      auto cached_entry = load(disk, next_height);
      if (!cached_entry)
        return cached_entry.error();

      std::optional<rpc::get_blocks_fast_response> cached_resp = std::move(*cached_entry);
      std::uint64_t request_start = next_height;
      if (cached_resp && !cached_resp->blocks.empty())
        request_start = cached_resp->start_height;
      else
        MWARNING("Cache missing entry covering height " << next_height);

      MINFO("Comparing cache batch starting at " << request_start << " against daemon for heights >= " << next_height);

      rpc::get_blocks_fast_response fetched{};
      {
        cryptonote::rpc::GetBlocksFast::Request req{};
        req.start_height = request_start;
        req.prune = false;

        auto message = rpc::client::make_message("get_blocks_fast", req);
        MONERO_CHECK(client.send(std::move(message), send_timeout));

        auto response = client.get_message(receive_timeout);
        if (!response)
          return response.error();

        auto parsed = rpc::parse_json_response<rpc::get_blocks_fast>(std::move(*response));
        if (!parsed)
          return parsed.error();
        if (parsed->blocks.empty())
          break;
        fetched = std::move(*parsed);
      }

      if (cached_resp && cached_resp->blocks.empty())
        cached_resp.reset();

      auto fetched_summary = summarize_response(fetched, next_height, target_height);
      if (!fetched_summary)
        return fetched_summary.error();
      if (fetched_summary->empty())
        break;

      std::unordered_map<std::uint64_t, crypto::hash> cache_map;
      if (cached_resp)
      {
        auto cached_summary = summarize_response(*cached_resp, next_height, target_height);
        if (!cached_summary)
          return cached_summary.error();
        for (const block_summary& summary : *cached_summary)
          cache_map.emplace(summary.height, summary.hash);
      }
      else
      {
        MWARNING("Cache missing entry covering height " << next_height);
        all_match = false;
      }

      std::uint64_t last_height = next_height - 1;
      for (const block_summary& summary : *fetched_summary)
      {
        if (remaining == 0 || summary.height > target_height)
          break;

        const auto it = cache_map.find(summary.height);
        if (it == cache_map.end())
        {
          MWARNING("Cache missing block at height " << summary.height);
          all_match = false;
        }
        else
        {
          if (it->second != summary.hash)
          {
            MWARNING(
              "Cache mismatch at height " << summary.height << ": cache "
              << epee::string_tools::pod_to_hex(it->second) << " daemon "
              << epee::string_tools::pod_to_hex(summary.hash)
            );
            all_match = false;
          }
          cache_map.erase(it);
        }

        last_height = summary.height;
        if (remaining)
          --remaining;
      }

      for (const auto& extra : cache_map)
      {
        if (extra.first <= target_height)
        {
          MWARNING("Cache contains extra block at height " << extra.first);
          all_match = false;
        }
      }

      if (last_height < next_height)
        break;

      next_height = last_height + 1;
    }

    if (all_match && remaining == 0)
    {
      MINFO("Cache verification completed successfully");
      return success();
    }

    if (!all_match)
      return {lws::error::bad_blockchain};

    MWARNING("Cache verification ended before completing requested range");
    return {lws::error::bad_blockchain};
  }
} // namespace block_cache
} // namespace lws
