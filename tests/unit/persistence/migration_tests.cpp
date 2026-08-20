#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

#include "persistence/migrations.h"

namespace vhsm::persistence {

namespace {

// Helper: register a chain of simple appends so each migration is observable
// in the produced bytes.
void register_chain(MigrationRegistry &reg) {
  reg.register_migration(1, [](std::vector<u8> in) {
    in.push_back('a');
    return in;
  });
  reg.register_migration(2, [](std::vector<u8> in) {
    in.push_back('b');
    return in;
  });
  reg.register_migration(3, [](std::vector<u8> in) {
    in.push_back('c');
    return in;
  });
}

} // namespace

TEST(MigrationRegistryTest, AppliesChainInOrder) {
  MigrationRegistry reg;
  register_chain(reg);

  std::vector<u8> data;
  data.push_back('x');
  auto out = reg.migrate(data, 1, 4);
  EXPECT_EQ(std::string(out.begin(), out.end()), "xabc");
}

TEST(MigrationRegistryTest, NoMigrationWhenAtTarget) {
  MigrationRegistry reg;
  register_chain(reg);

  std::vector<u8> data = {'z'};
  auto out = reg.migrate(data, 3, 3);
  EXPECT_EQ(out, data);
}

TEST(MigrationRegistryTest, RejectsDowngrade) {
  MigrationRegistry reg;
  register_chain(reg);
  EXPECT_THROW(reg.migrate({}, 3, 2), std::runtime_error);
}

TEST(MigrationRegistryTest, MissingStepThrows) {
  MigrationRegistry reg;
  reg.register_migration(1, [](std::vector<u8> in) {
    in.push_back('a');
    return in;
  });
  // No migration from version 2; jumping 1 -> 3 must fail.
  EXPECT_THROW(reg.migrate({}, 1, 3), std::runtime_error);
}

TEST(MigrationRegistryTest, DuplicateRegistrationRejected) {
  MigrationRegistry reg;
  reg.register_migration(1, [](std::vector<u8> in) {
    in.push_back('a');
    return in;
  });
  EXPECT_FALSE(reg.register_migration(1, [](std::vector<u8> in) {
    in.push_back('b');
    return in;
  }));
}

TEST(MigrationRegistryTest, CurrentVersionTracksChain) {
  MigrationRegistry reg;
  EXPECT_EQ(reg.current_version(), 1u);
  register_chain(reg);
  EXPECT_EQ(reg.current_version(), 4u);
}

TEST(MigrationRegistryTest, ClearResets) {
  MigrationRegistry reg;
  register_chain(reg);
  reg.clear();
  EXPECT_EQ(reg.current_version(), 1u);
  EXPECT_THROW(reg.migrate({}, 1, 2), std::runtime_error);
}

} // namespace vhsm::persistence