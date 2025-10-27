#pragma once

// Ensure the X-Cash provided header is available first.
#include "../external/monero/contrib/epee/include/hex.h"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/utility/string_ref.hpp>

#include "wipeable_string.h"
#include "span.h"

namespace
{
  inline int hex_char_to_int(const unsigned char value) noexcept
  {
    if ('0' <= value && value <= '9')
      return value - '0';
    if ('a' <= value && value <= 'f')
      return 10 + (value - 'a');
    if ('A' <= value && value <= 'F')
      return 10 + (value - 'A');
    return -1;
  }
}

namespace epee
{
  inline std::string to_hex::string(const span<const std::uint8_t> src)
  {
    if (std::numeric_limits<std::size_t>::max() / 2 < src.size())
      throw std::range_error("hex::string exceeded maximum size");

    std::string out(src.size() * 2, '\0');
    buffer_unchecked(&out[0], src);
    return out;
  }

  inline epee::wipeable_string to_hex::wipeable_string(const span<const std::uint8_t> src)
  {
    if (std::numeric_limits<std::size_t>::max() / 2 < src.size())
      throw std::range_error("hex::wipeable_string exceeded maximum size");

    std::string temp(src.size() * 2, '\0');
    buffer_unchecked(&temp[0], src);
    return epee::wipeable_string{temp};
  }

  inline void to_hex::buffer(std::ostream& out, const span<const std::uint8_t> src)
  {
    for (const std::uint8_t byte : src)
    {
      static constexpr const char table[] = "0123456789abcdef";
      out.put(table[byte >> 4]);
      out.put(table[byte & 0x0F]);
    }
  }

  inline void to_hex::formatted(std::ostream& out, const span<const std::uint8_t> src)
  {
    out.put('<');
    buffer(out, src);
    out.put('>');
  }

  inline void to_hex::buffer_unchecked(char* out, const span<const std::uint8_t> src) noexcept
  {
    static constexpr const char table[] = "0123456789abcdef";
    for (const std::uint8_t byte : src)
    {
      *out++ = table[byte >> 4];
      *out++ = table[byte & 0x0F];
    }
  }

  struct from_hex
  {
    static bool to_string(std::string& out, const boost::string_ref src)
    {
      out.resize(src.size() / 2);
      return to_buffer_unchecked(reinterpret_cast<std::uint8_t*>(&out[0]), src);
    }

    static bool to_buffer(span<std::uint8_t> out, const boost::string_ref src) noexcept
    {
      if (src.size() / 2 != out.size())
        return false;
      return to_buffer_unchecked(out.data(), src);
    }

    static bool to_buffer_unchecked(std::uint8_t* dest, const boost::string_ref src) noexcept
    {
      if (src.size() % 2 != 0)
        return false;

      const unsigned char* data = reinterpret_cast<const unsigned char*>(src.data());
      for (std::size_t i = 0; i < src.size(); i += 2)
      {
        const int hi = hex_char_to_int(data[i]);
        const int lo = hex_char_to_int(data[i + 1]);
        if (hi < 0 || lo < 0)
          return false;
        *dest++ = std::uint8_t((hi << 4) | lo);
      }
      return true;
    }
  };

  struct from_hex_locale
  {
    static std::vector<std::uint8_t> to_vector(const boost::string_ref src)
    {
      const auto include = [] (const char input) {
        return !std::isspace(static_cast<unsigned char>(input)) && input != ':';
      };

      const auto count = std::count_if(src.begin(), src.end(), include);
      if (count % 2)
        throw std::length_error{"Invalid hexadecimal input length"};

      std::vector<std::uint8_t> result;
      result.reserve(count / 2);

      auto it = src.begin();
      while (it != src.end())
      {
        while (it != src.end() && !include(*it))
          ++it;
        if (it == src.end())
          break;

        const int hi = hex_char_to_int(static_cast<unsigned char>(*it++));
        int lo = -1;
        while (it != src.end())
        {
          if (include(*it))
          {
            lo = hex_char_to_int(static_cast<unsigned char>(*it++));
            break;
          }
          ++it;
        }
        if (hi < 0 || lo < 0)
          throw std::invalid_argument{"Invalid hex digit"};
        result.push_back(std::uint8_t((hi << 4) | lo));
      }
      return result;
    }
  };
} // namespace epee

namespace lws
{
namespace compat
{
namespace hex
{
  inline bool to_buffer(epee::span<std::uint8_t> dest, const boost::string_ref value) noexcept
  {
    return epee::from_hex::to_buffer(dest, value);
  }

  template<typename T>
  inline bool to_pod(T& dest, const boost::string_ref value) noexcept
  {
    return to_buffer(epee::as_mut_byte_span(dest), value);
  }
} // namespace hex
} // namespace compat
} // namespace lws
