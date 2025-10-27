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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "span.h"

namespace epee
{
  struct byte_slice_data;
  class byte_stream;

  struct release_byte_slice
  {
    static void call(void*, void* ptr) noexcept;
    void operator()(byte_slice_data* ptr) const noexcept
    {
      call(nullptr, ptr);
    }
  };

  struct release_byte_buffer
  {
    void operator()(std::uint8_t* buf) const noexcept;
  };

  class byte_slice
  {
    std::unique_ptr<byte_slice_data, release_byte_slice> storage_;
    span<const std::uint8_t> portion_;

    byte_slice(byte_slice_data* storage, span<const std::uint8_t> portion) noexcept;

    struct adapt_buffer{};

    template<typename T>
    explicit byte_slice(const adapt_buffer, T&& buffer);

  public:
    using value_type = std::uint8_t;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = const std::uint8_t*;
    using const_pointer = const std::uint8_t*;
    using reference = std::uint8_t;
    using const_reference = std::uint8_t;
    using iterator = pointer;
    using const_iterator = const_pointer;

    byte_slice() noexcept
      : storage_(nullptr), portion_()
    {}

    byte_slice(std::nullptr_t) noexcept
      : byte_slice()
    {}

    explicit byte_slice(std::initializer_list<span<const std::uint8_t>> sources);

    explicit byte_slice(std::vector<std::uint8_t>&& buffer);

    explicit byte_slice(std::string&& buffer);

    explicit byte_slice(byte_stream&& stream, bool shrink = true);

    byte_slice(byte_slice&& source) noexcept;
    ~byte_slice() noexcept = default;

    byte_slice& operator=(byte_slice&&) noexcept;

    byte_slice clone() const noexcept { return {storage_.get(), portion_}; }

    iterator begin() const noexcept { return portion_.begin(); }
    const_iterator cbegin() const noexcept { return portion_.begin(); }

    iterator end() const noexcept { return portion_.end(); }
    const_iterator cend() const noexcept { return portion_.end(); }

    bool empty() const noexcept { return storage_ == nullptr; }
    const std::uint8_t* data() const noexcept { return portion_.data(); }
    std::size_t size() const noexcept { return portion_.size(); }

    std::size_t remove_prefix(std::size_t max_bytes) noexcept;

    byte_slice take_slice(std::size_t max_bytes) noexcept;

    byte_slice get_slice(std::size_t begin, std::size_t end) const;

    std::unique_ptr<byte_slice_data, release_byte_slice> take_buffer() noexcept;
  };

  using byte_buffer = std::unique_ptr<std::uint8_t, release_byte_buffer>;

  byte_buffer byte_buffer_resize(byte_buffer buf, std::size_t length) noexcept;

  byte_buffer byte_buffer_increase(byte_buffer buf, std::size_t current, std::size_t more);
} // epee
