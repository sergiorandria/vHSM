#include <gtest/gtest.h>

#include "../../../src/keystore/hsm_object.h"

using namespace vhsm::keystore;

// Test-derived class to expose protected wipe()
class TestHsmObject : public HsmObject {
public:
    using HsmObject::HsmObject; // inherit constructors
    void wipe_public() { wipe();
    }
};

TEST(HsmObject, ConstructorAndGetters) {
    HsmObject obj(ObjectType::SECRET_KEY, true, false);

    EXPECT_EQ(obj.getType(), ObjectType::SECRET_KEY);
    EXPECT_TRUE(obj.isSensitive());
    EXPECT_FALSE(obj.isExtractable());
}

TEST(HsmObject, SetAndGetId) {
    HsmObject obj(ObjectType::SECRET_KEY);

    std::vector<unsigned char> id = {0x01, 0x02, 0x03, 0x04};
    obj.setId(id);

    auto span = obj.getId();
    EXPECT_EQ(span.size(), id.size());
    EXPECT_TRUE(std::equal(span.begin(), span.end(), id.begin()));
}

TEST(HsmObject, DefaultSensitiveAndExtractable) {
    // Default constructor values: sensitive = false, extractable = true
    HsmObject obj(ObjectType::DATA);
    EXPECT_FALSE(obj.isSensitive());
    EXPECT_TRUE(obj.isExtractable());
}

TEST(HsmObject, Wipe) {
    TestHsmObject obj(ObjectType::SECRET_KEY);
    std::vector<unsigned char> id = {0x01, 0x02, 0x03};
    obj.setId(id);

    obj.wipe_public();

    EXPECT_EQ(obj.getId().size(), 0u);
    EXPECT_FALSE(obj.isSensitive());
    EXPECT_FALSE(obj.isExtractable());
}

TEST(HsmObject, MoveSemantics) {
    HsmObject obj1(ObjectType::SECRET_KEY);
    std::vector<unsigned char> id = {0x01, 0x02};
    obj1.setId(id);

    HsmObject obj2 = std::move(obj1);

    // After move, obj1 should be in a default-constructed-like state (ObjectType::OTHER, not sensitive, not extractable, empty id)
    EXPECT_EQ(obj1.getType(), ObjectType::OTHER);
    EXPECT_FALSE(obj1.isSensitive());
    EXPECT_FALSE(obj1.isExtractable());
    EXPECT_EQ(obj1.getId().size(), 0u);

    // obj2 should have the moved values
    EXPECT_EQ(obj2.getType(), ObjectType::SECRET_KEY);
    EXPECT_FALSE(obj2.isSensitive()); // default
    EXPECT_TRUE(obj2.isExtractable()); // default
    auto span = obj2.getId();
    EXPECT_EQ(span.size(), id.size());
    EXPECT_TRUE(std::equal(span.begin(), span.end(), id.begin()));
}

TEST(HsmObject, CopySemanticsThrowsForSensitive) {
    HsmObject sensitiveObj(ObjectType::SECRET_KEY, true, true);
    EXPECT_THROW({
        HsmObject copy = sensitiveObj;
    }, std::runtime_error);

    HsmObject nonSensitiveObj(ObjectType::DATA, false, true);
    // Copying non-sensitive should be allowed
    EXPECT_NO_THROW({
        HsmObject copy = nonSensitiveObj;
    });
}