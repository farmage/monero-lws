// Copyright (c) 2019-2022, The Monero Project
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

#include <memory>
#include <string>
#include <system_error>
#include <zmq.h>

#include "common/expect.h"
#include "span.h"

#define MONERO_ZMQ_CHECK(...)                      \
    do                                             \
    {                                              \
        if (( __VA_ARGS__ ) < 0)                   \
            return {::net::zmq::get_error_code()}; \
    } while (0)

#define MONERO_LOG_ZMQ_ERROR(...)                                                   \
    do                                                                              \
    {                                                                               \
        MERROR( __VA_ARGS__ << ": " << ::net::zmq::get_error_code().message());     \
    } while (0)

#define MONERO_ZMQ_THROW(msg)                         \
    MONERO_THROW( ::net::zmq::get_error_code(), msg )

namespace epee
{
    class byte_slice;
}

namespace net
{
namespace zmq
{
    const std::error_category& error_category() noexcept;

    inline std::error_code make_error_code(int code) noexcept
    {
        return std::error_code{code, error_category()};
    }

    inline std::error_code get_error_code() noexcept
    {
        return make_error_code(zmq_errno());
    }

    class terminate
    {
        static void call(void* ptr) noexcept;
    public:
        void operator()(void* ptr) const noexcept
        {
            if (ptr)
                call(ptr);
        }
    };

    struct close
    {
        void operator()(void* ptr) const noexcept
        {
            if (ptr)
                zmq_close(ptr);
        }
    };

    using context = std::unique_ptr<void, terminate>;
    using socket = std::unique_ptr<void, close>;

    template<typename F, typename... T>
    expect<void> retry_op(F op, T&&... args) noexcept(noexcept(op(args...)))
    {
      for (;;)
      {
        if (0 <= op(args...))
          return success();

        const int error = zmq_errno();
        if (error != EINTR)
          return make_error_code(error);
      }
    }

    expect<std::string> receive(void* socket, int flags = 0);
    expect<void> send(epee::span<const std::uint8_t> payload, void* socket, int flags = 0) noexcept;
    expect<void> send(epee::byte_slice&& payload, void* socket, int flags = 0) noexcept;
} // namespace zmq
} // namespace net
