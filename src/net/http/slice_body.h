// Copyright (c) 2024, The Monero Project
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

#include <boost/asio/buffer.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/http/message.hpp>
#include <cstdint>
#include <limits>
#include "compat/epee/byte_slice.h"

namespace net { namespace http
{
  //! Trait for `boost::beast` body type
  struct slice_body
  {
    using value_type = epee::byte_slice;

    static std::uint64_t size(const value_type& source) noexcept
    {
      static_assert(!std::numeric_limits<std::size_t>::is_signed, "expected unsigned");
      static_assert(
        std::numeric_limits<std::size_t>::max() <= std::numeric_limits<std::uint64_t>::max(),
        "unexpected size_t max value"
      );
      return source.size();
    }

    struct writer
    {
      epee::byte_slice body_;

      using const_buffers_type = boost::asio::const_buffer;

      template<bool is_request, typename Fields>
      explicit writer(boost::beast::http::header<is_request, Fields> const&, value_type const& body)
        : body_(body.clone())
      {}

      void init(boost::beast::error_code& ec)
      {
        ec = {};
      }

      boost::optional<std::pair<const_buffers_type, bool>> get(boost::beast::error_code& ec)
      {
        ec = {};
        return {{const_buffers_type{body_.data(), body_.size()}, false}};
      }
    };
  };
}} // net // http
