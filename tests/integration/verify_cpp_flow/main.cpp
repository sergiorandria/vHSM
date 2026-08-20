#include "../../../src/admin/admin.h"
#include <exception>
#include <gtest/gtest.h>

TEST(AdminAuthentification, JustLogin) {
  try {
    auto id = get_admin_id();
    auto hpass = get_admin_hpass();
  } catch (std::exception &e) {
    std::cerr << "One of the id or the pass is not defined" << std::endl;
  }

  ASSERT_EQ(0, 0);
}