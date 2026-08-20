#include <fstream>
#include <iterator>

#include <filesystem>
#include <gtest/gtest.h>

#include "persistence/vault.h"
#include "persistence/vault_format.h"
#include "core/types.h"

namespace vhsm::persistence {

class VaultTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = std::filesystem::temp_directory_path() / "vhsm_vault_test";
        std::filesystem::create_directories(dir_);
    }

    void TearDown() override {
        std::filesystem::remove_all(dir_);
    }

    std::filesystem::path dir_;
};

TEST_F(VaultTest, CreateAndLoadRoundTrip) {
    auto path = dir_ / "vault.bin";
    const std::vector<u8> payload = {'h', 'e', 'l', 'l', 'o', 0x00, 0xFF};

    auto vault = Vault::create(path, "correct horse", payload);
    EXPECT_TRUE(vault.is_valid());
    EXPECT_EQ(vault.load(), payload);
    EXPECT_EQ(vault.version(), kVaultFormatVersion);
}

TEST_F(VaultTest, WrongPasswordFails) {
    auto path = dir_ / "vault.bin";
    Vault::create(path, "secret", {1, 2, 3});

    EXPECT_THROW(Vault(path, "wrong"), std::runtime_error);
}

TEST_F(VaultTest, OpenExistingAndResave) {
    auto path = dir_ / "vault.bin";
    Vault::create(path, "pw", {9, 9});

    Vault reopened(path, "pw");
    EXPECT_TRUE(reopened.is_valid());

    const std::vector<u8> newer = {4, 5, 6, 7};
    reopened.save(newer);

    Vault again(path, "pw");
    EXPECT_EQ(again.load(), newer);
}

TEST_F(VaultTest, TamperedFileFailsAuth) {
    auto path = dir_ / "vault.bin";
    Vault::create(path, "pw", {1, 2, 3});

    std::vector<u8> bytes;
    {
        std::ifstream in(path, std::ios::binary);
        bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    ASSERT_GT(bytes.size(), 1u);
    bytes[bytes.size() - 1] ^= 0xFF;  // corrupt the final byte (GCM tag)

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    out.close();

    EXPECT_THROW(Vault(path, "pw"), std::runtime_error);
}

TEST_F(VaultTest, MissingFileThrows) {
    EXPECT_THROW(Vault(dir_ / "nope.bin", "pw"), std::runtime_error);
}

} // namespace vhsm::persistence