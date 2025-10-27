#pragma once

#if defined(__cplusplus) && __cplusplus >= 201703L

namespace std
{
  template<typename Arg, typename Result>
  struct unary_function
  {
    using argument_type = Arg;
    using result_type = Result;
  };

  template<typename Arg1, typename Arg2, typename Result>
  struct binary_function
  {
    using first_argument_type = Arg1;
    using second_argument_type = Arg2;
    using result_type = Result;
  };
}

#endif
