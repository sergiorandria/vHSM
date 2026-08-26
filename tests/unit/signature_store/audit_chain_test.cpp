#include "../../src/audit/audit_log.h"

#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>

using vhsm::audit::HashChainedAuditLog;

namespace {
std::string tmp_path(const char *name) {
  return std::string(::testing::TempDir()) + name;
}
} // namespace

TEST(AuditHashChain, AppendAndVerifyIntact) {
  const auto path = tmp_path("audit_intact.log");
  std::remove(path.c_str());

  HashChainedAuditLog log(path, {1, 2, 3, 4});
  (void)log.append("evt-1", "C_LOGIN");
  (void)log.append("evt-2", "C_SIGN");
  (void)log.append("evt-3", "C_LOGOUT");

  EXPECT_EQ(log.verify_chain(), std::nullopt);
  EXPECT_NE(log.tail_hash(), std::string(64, '0'));
}

TEST(AuditHashChain, TamperedRecordDetected) {
  const auto path = tmp_path("audit_tamper.log");
  std::remove(path.c_str());

  HashChainedAuditLog log(path, {9, 9, 9, 9});
  (void)log.append("evt-1", "C_LOGIN");
  (void)log.append("evt-2", "C_SIGN");

  // Rewrite line 1's event type in place (same length).
  {
    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    const auto p = content.find("C_LOGIN");
    ASSERT_NE(p, std::string::npos);
    content.replace(p, 7, "C_HACK!");
    std::ofstream out(path, std::ios::trunc);
    out << content;
  }

  EXPECT_EQ(log.verify_chain(), 1u);
}

TEST(AuditHashChain, DeletedRecordBreaksChain) {
  const auto path = tmp_path("audit_delete.log");
  std::remove(path.c_str());

  HashChainedAuditLog log(path, {7, 7, 7});
  (void)log.append("evt-1", "A");
  (void)log.append("evt-2", "B");
  (void)log.append("evt-3", "C");

  // Delete the middle record.
  {
    std::ifstream in(path);
    std::vector<std::string> lines;
    std::string l;
    while (std::getline(in, l))
      lines.push_back(l + "\n");
    ASSERT_EQ(lines.size(), 3u);
    lines.erase(lines.begin() + 1);
    std::ofstream out(path, std::ios::trunc);
    for (auto &x : lines)
      out << x;
  }

  EXPECT_EQ(log.verify_chain(), 2u);
}

TEST(AuditHashChain, TailRecoveryAcrossRestart) {
  const auto path = tmp_path("audit_restart.log");
  std::remove(path.c_str());

  std::string tail1;
  {
    HashChainedAuditLog log(path, {5, 5});
    (void)log.append("e1", "T1");
    tail1 = log.tail_hash();
  }
  {
    // Fresh instance recovers seq/tail from the file and continues the chain.
    HashChainedAuditLog log2(path, {5, 5});
    (void)log2.append("e2", "T2");
    EXPECT_EQ(log2.verify_chain(), std::nullopt);
    EXPECT_NE(tail1, log2.tail_hash());
  }
}
