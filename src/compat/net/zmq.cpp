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

#include "compat/net/zmq.h"

#include <cassert>
#include <cerrno>
#include <limits>
#include <utility>

#include "compat/epee/byte_slice.h"

namespace net
{
namespace zmq
{
    const std::error_category& error_category() noexcept
    {
        struct category final : std::error_category
        {
            virtual const char* name() const noexcept override final
            {
                return "error::error_category()";
            }

            virtual std::string message(int value) const override final
            {
                const char* const msg = zmq_strerror(value);
                if (msg)
                    return msg;
                return "zmq_strerror failure";
            }

            virtual std::error_condition default_error_condition(int value) const noexcept override final
            {
                switch (value)
                {
                case EFSM:
                case ETERM:
                    break;
                default:
                    return std::errc(value);
                }
                return std::error_condition{value, *this};
            }

        };
        static const category instance{};
        return instance;
    }

    void terminate::call(void* ptr) noexcept
    {
        assert(ptr != nullptr);
        while (zmq_term(ptr))
        {
            if (zmq_errno() != EINTR)
                break;
        }
    }

    namespace
    {
        class message
        {
            zmq_msg_t handle_;

        public:
            message() noexcept
              : handle_()
            {
                zmq_msg_init(handle());
            }

            message(message&&) = delete;
            message(const message&) = delete;
            message& operator=(message&&) = delete;
            message& operator=(const message&) = delete;

            ~message() noexcept
            {
                zmq_msg_close(handle());
            }

            zmq_msg_t* handle() noexcept
            {
                return std::addressof(handle_);
            }

            const char* data() noexcept
            {
                return static_cast<const char*>(zmq_msg_data(handle()));
            }

            std::size_t size() noexcept
            {
                return zmq_msg_size(handle());
            }
        };

        struct do_receive
        {
            int operator()(std::string& payload, void* const socket, const int flags) const
            {
                static constexpr const int max_out = std::numeric_limits<int>::max();
                const std::string::size_type initial = payload.size();
                message part{};
                for (;;)
                {
                    int last = 0;
                    if ((last = zmq_msg_recv(part.handle(), socket, flags)) < 0)
                        return last;

                    payload.append(part.data(), part.size());
                    if (!zmq_msg_more(part.handle()))
                        break;
                }
                const std::string::size_type added = payload.size() - initial;
                return unsigned(max_out) < added ? max_out : int(added);
            }
        };
    } // anonymous

    expect<std::string> receive(void* const socket, const int flags)
    {
        std::string payload{};
        MONERO_CHECK(retry_op(do_receive{}, payload, socket, flags));
        return {std::move(payload)};
    }

    expect<void> send(const epee::span<const std::uint8_t> payload, void* const socket, const int flags) noexcept
    {
        return retry_op(zmq_send, socket, payload.data(), payload.size(), flags);
    }

    expect<void> send(epee::byte_slice&& payload, void* socket, int flags) noexcept
    {
        void* const data = const_cast<std::uint8_t*>(payload.data());
        const std::size_t size = payload.size();
        auto buffer = payload.take_buffer();

        zmq_msg_t msg{};
        MONERO_ZMQ_CHECK(zmq_msg_init_data(std::addressof(msg), data, size, epee::release_byte_slice::call, buffer.get()));
        buffer.release();

        expect<void> sent = retry_op(zmq_msg_send, std::addressof(msg), socket, flags);
        if (!sent)
            zmq_msg_close(std::addressof(msg));
        return sent;
    }
} // namespace zmq
} // namespace net
