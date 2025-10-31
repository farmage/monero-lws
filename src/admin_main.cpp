// Copyright (c) 2018-2020, The Monero Project
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
#include <chrono>
#include <optional>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "block_cache.h"
#include "common/command_line.h" // monero/src
#include "common/expect.h"       // monero/src
#include "config.h"
#include "cryptonote_config.h"   // monero/src
#include "error.h"
#include "compat/hex.h"
#include "db/storage.h"
#include "db/string.h"
#include "options.h"
#include "misc_log_ex.h"  // monero/contrib/epee/include
#include "rpc/admin.h"
#include "rpc/client.h"
#include "span.h"         // monero/contrib/epee/include
#include "string_tools.h" // monero/contrib/epee/include
#include "wire/adapted/crypto.h"
#include "wire/filters.h"
#include "wire/json/write.h"
#include "wire/wrapper/array.h"
#include "wire/wrappers_impl.h"

namespace
{
  std::string default_daemon_address()
  {
    static constexpr const char base[] = "tcp://127.0.0.1:";
    switch (lws::config::network)
    {
    case cryptonote::TESTNET:
      return base + std::to_string(config::testnet::ZMQ_RPC_DEFAULT_PORT);
    case cryptonote::STAGENET:
      return base + std::to_string(config::stagenet::ZMQ_RPC_DEFAULT_PORT);
    case cryptonote::MAINNET:
    default:
      break;
    }
    return base + std::to_string(config::ZMQ_RPC_DEFAULT_PORT);
  }

  // wrapper for custom output for admin accounts
  template<typename T>
  struct admin_display
  {
    T value;
  };

  void write_bytes(wire::json_writer& dest, const admin_display<lws::db::account>& source)
  {
    wire::object(dest,
      wire::field("address", lws::db::address_string(source.value.address)),
      wire::field("key", std::cref(source.value.key))
    );
  }

  void write_bytes(wire::json_writer& dest, admin_display<boost::iterator_range<lmdb::value_iterator<lws::db::account>>> source)
  {
    const auto filter = [](const lws::db::account& src)
    { return bool(src.flags & lws::db::account_flags::admin_account); };
    const auto transform = [] (lws::db::account src)
    { return admin_display<lws::db::account>{std::move(src)}; };

    wire_write::bytes(dest, wire::array(source.value | boost::adaptors::filtered(filter) | boost::adaptors::transformed(transform)));
  }

  template<typename F, typename... T>
  void run_command(F f, std::ostream& dest, T&&... args)
  {
    wire::json_stream_writer stream{dest};
    MONERO_UNWRAP(f(stream, std::forward<T>(args)...));
    stream.finish();
  }

  struct options : lws::options
  {
    const command_line::arg_descriptor<bool> show_sensitive;
    const command_line::arg_descriptor<std::string> command;
    const command_line::arg_descriptor<std::vector<std::string>> arguments;
    const command_line::arg_descriptor<std::string> daemon_rpc;
    const command_line::arg_descriptor<std::string> daemon_sub;

    options()
      : lws::options()
      , show_sensitive{"show-sensitive", "Show view keys", false}
      , command{"command", "Admin command to execute", ""}
      , arguments{"arguments", "Arguments to command"}
      , daemon_rpc{"daemon", "<protocol>://<address>:<port> of a monerod ZMQ RPC", ""}
      , daemon_sub{"sub", "tcp://address:port or ipc://path of a monerod ZMQ Pub (optional)", ""}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);
      command_line::add_arg(description, show_sensitive);
      command_line::add_arg(description, command);
      command_line::add_arg(description, arguments);
      command_line::add_arg(description, daemon_rpc);
      command_line::add_arg(description, daemon_sub);
    }
  };

  struct program
  {
    lws::db::storage disk;
    std::vector<std::string> arguments;
    bool show_sensitive;
    std::string daemon_rpc;
    std::string daemon_sub;
  };

  crypto::secret_key get_key(std::string const& hex)
  {
    crypto::secret_key out{};
    if (!epee::string_tools::hex_to_pod(hex, out))
      MONERO_THROW(lws::error::bad_view_key, "View key has invalid hex");
    return out;
  }

  std::vector<lws::db::account_address> get_addresses_(epee::span<const std::string> arguments)
  {
    std::vector<lws::db::account_address> addresses{};
    addresses.reserve(arguments.size());
    for (std::string const& address : arguments)
      addresses.push_back(lws::db::address_string(address).value());
    return addresses;
  }

  std::vector<lws::db::account_address> get_addresses(epee::span<const std::string> arguments)
  {
    // first entry is currently always some other option
    assert(!arguments.empty());
    arguments.remove_prefix(1);
    return get_addresses_(arguments);
  }

  void accept_requests(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      throw std::runtime_error{"accept_requests requires 2 or more arguments"};

    lws::rpc::address_requests req{
      get_addresses(epee::to_span(prog.arguments)),
      MONERO_UNWRAP(lws::db::request_from_string(prog.arguments[0]))
    };
    run_command(lws::rpc::accept_requests, out, std::move(prog.disk), std::move(req));
  }

  void add_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 2)
      throw std::runtime_error{"add_account needs exactly two arguments"};

    lws::rpc::add_account_req req{
      lws::db::address_string(prog.arguments[0]).value(),
      get_key(prog.arguments[1])
    };
    run_command(lws::rpc::add_account, out, std::move(prog.disk), std::move(req));
  }

  void create_admin(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"create_admin takes zero arguments"};

    admin_display<lws::db::account> account{};
    {
      crypto::secret_key auth{};
      crypto::generate_keys(account.value.address.view_public, auth);
      MONERO_UNWRAP(prog.disk.add_account(account.value.address, auth, lws::db::account_flags::admin_account));

      static_assert(sizeof(auth) == sizeof(account.value.key), "bad memcpy");
      std::memcpy(std::addressof(account.value.key), std::addressof(auth), sizeof(auth));
    }

    wire::json_stream_writer json{out};
    write_bytes(json, account);
    json.finish();
  }

  void debug_database(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"debug_database takes zero arguments"};

    auto reader = prog.disk.start_read().value();
    reader.json_debug(out, prog.show_sensitive);
  }

  void verify_cache(program prog, std::ostream& out)
  {
    std::uint64_t start_height = 0;
    std::size_t count = 10000;

    if (!prog.arguments.empty())
      start_height = std::stoull(prog.arguments[0]);
    if (1 < prog.arguments.size())
      count = std::stoull(prog.arguments[1]);
    if (count == 0)
      throw std::runtime_error{"verify_cache requires count > 0"};

    if (prog.daemon_rpc.empty())
      prog.daemon_rpc = default_daemon_address();

    auto ctx = lws::rpc::context::make(
      prog.daemon_rpc,
      prog.daemon_sub,
      {},
      {},
      std::chrono::minutes{0},
      false
    );

    auto client = MONERO_UNWRAP(ctx.connect());
    auto status = lws::block_cache::verify(prog.disk, std::move(client), start_height, count);
    if (!status)
      MONERO_THROW(status.error(), "Cache verification failed");

    wire::json_stream_writer json{out};
    wire::object(json,
      wire::field("start_height", start_height),
      wire::field("count", count),
      wire::field("status", std::string{"ok"})
    );
    json.finish();
  }

  void force_sync(program prog, std::ostream& out)
  {
    std::uint64_t start_height = 0;
    std::optional<std::uint64_t> stop_height;
    if (!prog.arguments.empty())
      start_height = std::stoull(prog.arguments[0]);
    if (2 <= prog.arguments.size())
      stop_height = std::stoull(prog.arguments[1]);
    if (stop_height && *stop_height < start_height)
      throw std::runtime_error{"stop_height must be greater than or equal to start_height"};

    if (prog.daemon_rpc.empty())
      prog.daemon_rpc = default_daemon_address();

    auto ctx = lws::rpc::context::make(
      prog.daemon_rpc,
      prog.daemon_sub,
      {},
      {},
      std::chrono::minutes{0},
      false
    );

    auto client = MONERO_UNWRAP(ctx.connect());
    auto result = MONERO_UNWRAP(lws::block_cache::warm(prog.disk, std::move(client), start_height, stop_height));

    wire::json_stream_writer json{out};
    wire::object(json,
      wire::field("cached_from", result.cached_from),
      wire::field("cached_to", result.cached_to),
      wire::field("batches", result.batches)
    );
    json.finish();
  }

  void list_accounts(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_accounts takes zero arguments"};
    run_command(lws::rpc::list_accounts, out, std::move(prog.disk));
  }

  void list_admin(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_admin takes zero arguments"};

    using value_range = boost::iterator_range<lmdb::value_iterator<lws::db::account>>;
    const auto transform = [] (value_range user)
    { return admin_display<value_range>{std::move(user)}; };

    auto reader = MONERO_UNWRAP(prog.disk.start_read());
    wire::json_stream_writer json{out};
    wire::dynamic_object(
      json, reader.get_accounts().value().make_range(), wire::enum_as_string, transform
    );
    json.finish();
  }

  void list_requests(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_requests takes zero arguments"};
    run_command(lws::rpc::list_requests, out, std::move(prog.disk));
  }

  void modify_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      throw std::runtime_error{"modify_account_status requires 2 or more arguments"};

    lws::rpc::modify_account_req req{
      get_addresses(epee::to_span(prog.arguments)),
      lws::db::account_status_from_string(prog.arguments[0]).value()
    };
    run_command(lws::rpc::modify_account, out, std::move(prog.disk), std::move(req));
  }

  void reject_requests(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      MONERO_THROW(common_error::kInvalidArgument, "reject_requests requires 2 or more arguments");

    lws::rpc::address_requests req{
      get_addresses(epee::to_span(prog.arguments)),
      lws::db::request_from_string(prog.arguments[0]).value()
    };
    run_command(lws::rpc::reject_requests, out, std::move(prog.disk), std::move(req));
  }

  void rescan(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      throw std::runtime_error{"rescan requires 2 or more arguments"};

    lws::rpc::rescan_req req{
      get_addresses(epee::to_span(prog.arguments)),
      lws::db::block_id(std::stoull(prog.arguments[0]))
    };
    run_command(lws::rpc::rescan, out, std::move(prog.disk), std::move(req));
  }

  void rollback(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"rollback requires 1 argument"};

    const auto height = lws::db::block_id(std::stoull(prog.arguments[0]));
    MONERO_UNWRAP(prog.disk.rollback(height));

    wire::json_stream_writer json{out};
    wire::object(json, wire::field("new_height", height));
    json.finish();
  }

  void webhook_delete(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 1)
      throw std::runtime_error{"webhook_delete requires 1 or more arguments"};

    lws::rpc::webhook_delete_req req{
      get_addresses_(epee::to_span(prog.arguments))
    };
    run_command(lws::rpc::webhook_delete, out, std::move(prog.disk), std::move(req));
  }

  void webhook_delete_uuid(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 1)
      throw std::runtime_error{"webhook_delete_uuid requires 1 or more arguments"};

    std::vector<boost::uuids::uuid> ids{};
    ids.reserve(prog.arguments.size());
    for (const auto id : prog.arguments)
    {
      ids.emplace_back();
      if (!lws::compat::hex::to_pod(ids.back(), id))
        throw std::runtime_error{"webhook_delete_uuid given invalid event_id/uuid"};
    }

    lws::rpc::webhook_delete_uuid_req req{std::move(ids)};
    run_command(lws::rpc::webhook_delete_uuid, out, std::move(prog.disk), std::move(req));
  }

  struct command
  {
    char const* const name;
    void (*const handler)(program, std::ostream&);
    char const* const parameters;
  };

  static constexpr const command commands[] =
  {
    {"accept_requests",       &accept_requests, "<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"add_account",           &add_account,     "<base58 address> <view key hex>"},
    {"create_admin",          &create_admin,    ""},
    {"debug_database",        &debug_database,  ""},
    {"force_sync",            &force_sync,      "[start_height] [stop_height]"},
    {"list_accounts",         &list_accounts,   ""},
    {"list_admin",            &list_admin,      ""},
    {"list_requests",         &list_requests,   ""},
    {"modify_account_status", &modify_account,  "<\"active\"|\"inactive\"|\"hidden\"> <base58 address> [base 58 address]..."},
    {"reject_requests",       &reject_requests, "<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"rescan",                &rescan,          "<height> <base58 address> [base 58 address]..."},
    {"rollback",              &rollback,        "<height>"},
    {"verify_cache",          &verify_cache,    "[start_height] [count]"},
    {"webhook_delete",        &webhook_delete,  "<base58 address> [base 58 address]..."},
    {"webhook_delete_uuid",   &webhook_delete_uuid, "<event_id> [event_id]..."}
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options] [command] [arguments]" << std::endl;
    out << description << std::endl;
    out << "Commands:" << std::endl;
    for (command cmd : commands)
    {
      out << "  " << cmd.name << "\t\t" << cmd.parameters << std::endl;
    }
  }

  boost::optional<std::pair<std::string, program>> get_program(int argc, char** argv)
  {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
      po::options_description description{"Options"};
      opts.prepare(description);

      po::positional_options_description positional{};
      positional.add(opts.command.name, 1);
      positional.add(opts.arguments.name, -1);

      po::store(
        po::command_line_parser(argc, argv)
        .options(description).positional(positional).run()
        , args
      );
      po::notify(args);
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
      print_help(std::cout);
      return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/

    program prog{
      lws::db::storage::open(command_line::get_arg(args, opts.db_path).c_str(), 0)
    };

    prog.show_sensitive = command_line::get_arg(args, opts.show_sensitive);
    prog.daemon_rpc = command_line::get_arg(args, opts.daemon_rpc);
    prog.daemon_sub = command_line::get_arg(args, opts.daemon_sub);
    auto cmd = args[opts.command.name];
    if (cmd.empty())
      throw std::runtime_error{"No command given"};

    prog.arguments = command_line::get_arg(args, opts.arguments);
    return {{cmd.as<std::string>(), std::move(prog)}};
  }

  void run(boost::string_ref name, program prog, std::ostream& out)
  {
    struct by_name
    {
      bool operator()(command const& left, command const& right) const noexcept
      {
        assert(left.name && right.name);
        return std::strcmp(left.name, right.name) < 0;
      }
      bool operator()(boost::string_ref left, command const& right) const noexcept
      {
        assert(right.name);
        return left < right.name;
      }
      bool operator()(command const& left, boost::string_ref right) const noexcept
      {
        assert(left.name);
        return left.name < right;
      }
    };

    assert(std::is_sorted(std::begin(commands), std::end(commands), by_name{}));
    const auto found = std::lower_bound(
      std::begin(commands), std::end(commands), name, by_name{}
    );
    if (found == std::end(commands) || found->name != name)
      throw std::runtime_error{"No such command"};

    assert(found->handler != nullptr);
    found->handler(std::move(prog), out);

    if (out.bad())
      MONERO_THROW(std::io_errc::stream, "Writing to stdout failed");

    out << std::endl;
  }
} // anonymous

int main (int argc, char** argv)
{
  try
  {
    boost::optional<std::pair<std::string, program>> prog;
    bool enable_console_logs = false;

    try
    {
      prog = get_program(argc, argv);
      if (prog && prog->first == "force_sync")
        enable_console_logs = true;
      else if (prog && prog->first == "verify_cache")
        enable_console_logs = true;
    }
    catch (std::exception const& e)
    {
      std::cerr << e.what() << std::endl << std::endl;
      print_help(std::cerr);
      return EXIT_FAILURE;
    }

    mlog_configure("", enable_console_logs, 0, 0);
    if (enable_console_logs)
      mlog_set_categories("*:INFO");

    if (prog)
      run(prog->first, std::move(prog->second), std::cout);
  }
  catch (std::exception const& e)
  {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "Unknown exception" << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
