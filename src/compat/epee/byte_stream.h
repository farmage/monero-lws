// Copyright (c) 2020-2022, The Monero Project

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

#include <cassert>
#include <cstdint>
#include <cstring>

#include "compat/epee/byte_slice.h"
#include "span.h"

namespace epee
{
  class byte_stream
  {
    byte_buffer buffer_;
    std::uint8_t* next_write_;
    const std::uint8_t* end_;

    void overflow(std::size_t requested);

    void check(std::size_t requested)
    {
      const std::size_t remaining = available();
      if (remaining < requested)
        overflow(requested);
    }

  public:
    using char_type = std::uint8_t;
    using Ch = char_type;

    byte_stream() noexcept
      : buffer_(nullptr),
        next_write_(nullptr),
        end_(nullptr)
    {}

    byte_stream(byte_stream&& rhs) noexcept;
    ~byte_stream() noexcept = default;
    byte_stream& operator=(byte_stream&& rhs) noexcept;

    const std::uint8_t* data() const noexcept { return buffer_.get(); }
    std::uint8_t* tellp() const noexcept { return next_write_; }
    std::size_t available() const noexcept { return static_cast<std::size_t>(end_ - next_write_); }
    std::size_t size() const noexcept { return static_cast<std::size_t>(next_write_ - buffer_.get()); }
    std::size_t capacity() const noexcept { return static_cast<std::size_t>(end_ - buffer_.get()); }

    void Flush() const noexcept
    {}

    void reserve(std::size_t more)
    {
      check(more);
    }

    void clear() noexcept { next_write_ = buffer_.get(); }

    void write(const std::uint8_t* ptr, std::size_t length)
    {
      check(length);
      std::memcpy(tellp(), ptr, length);
      next_write_ += length;
    }

    void write(const char* ptr, std::size_t length)
    {
      write(reinterpret_cast<const std::uint8_t*>(ptr), length);
    }

    void write(epee::span<const std::uint8_t> source)
    {
      write(source.data(), source.size());
    }

    void write(epee::span<const char> source)
    {
      write(source.data(), source.size());
    }

    void put(std::uint8_t ch)
    {
      check(1);
      put_unsafe(ch);
    }

    void Put(std::uint8_t ch)
    {
      put(ch);
    }

    void put_unsafe(std::uint8_t ch) noexcept
    {
      assert(1 <= available());
      *(tellp()) = ch;
      ++next_write_;
    }

    void put_n(std::uint8_t ch, std::size_t count)
    {
      check(count);
      std::memset(tellp(), ch, count);
      next_write_ += count;
    }

    void push_back(std::uint8_t ch)
    {
      put(ch);
    }

    byte_buffer take_buffer() noexcept;
  };

  inline void PutReserve(byte_stream& dest, std::size_t length)
  {
    dest.reserve(length);
  }
}
