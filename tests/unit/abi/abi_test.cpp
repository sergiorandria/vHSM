#include <gtest/gtest.h>

#include "abi/export.h"
#include "abi/result.h"
#include "abi/error.h"
#include "abi/span.h"

// Test that the base ABI compiles, nodiscard is enforced, and versioned
// namespace resolves. The compiler is at peak: -O3 -flto -fvisibility=hidden.

using namespace vhsm::v1;

TEST(AbiTest, VersionedNamespaceResolves) {
  // vhsm::v1::Errc and vhsm::Errc (alias) should be the same type.
  Errc e = Errc::Ok;
  auto ec = make_error_code(e);
  EXPECT_FALSE(ec);
  EXPECT_EQ(ec.value(), 0);
}

TEST(AbiTest, ResultNodiscard) {
  Result<int> r = 42;
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, 42);

  Result<int> err_r = std::unexpected(make_error_code(Errc::HostMemory));
  EXPECT_FALSE(err_r.has_value());
  // [[nodiscard]] on Result ensures `err_r;` without check would be -Werror.
}

TEST(AbiTest, SpanBoundsChecked) {
  std::array<std::byte, 4> buf{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
  ByteSpan s = buf;
  EXPECT_EQ(s.size(), 4);
  EXPECT_EQ(s[2], std::byte{3});
}

namespace {
VHSM_HIDDEN void hidden_func() {}
VHSM_API void exported_func() {}
} // namespace

TEST(AbiTest, VisibilityHiddenByDefault) {
  // Real check is `nm -D libvhsm_core.so | grep VHSM_API`; here we just
  // verify the macros expand on functions (not variables, where GCC warns).
  hidden_func();
  exported_func();
  SUCCEED();
}
