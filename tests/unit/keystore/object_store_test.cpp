#include <gtest/gtest.h>

#include "../../../src/keystore/object_store.h"

using namespace vhsm::keystore;

TEST(ObjectStore, CreateAndGetObject) {
    ObjectStore store;

    auto [handle, objPtr] = store.createObject<HsmObject>(ObjectType::SECRET_KEY);
    EXPECT_NE(handle, CK_INVALID_HANDLE);
    EXPECT_NE(objPtr, nullptr);

    // Retrieve the object
    HsmObject* retrieved = store.getObject(handle);
    EXPECT_EQ(retrieved, objPtr);
    EXPECT_NE(retrieved, nullptr);

    // Check that the object is of the correct type
    EXPECT_EQ(retrieved->getType(), ObjectType::SECRET_KEY);
}

TEST(ObjectStore, DestroyObject) {
    ObjectStore store;

    auto [handle, objPtr] = store.createObject<HsmObject>(ObjectType::SECRET_KEY);
    EXPECT_NE(handle, CK_INVALID_HANDLE);

    // Destroy the object
    bool destroyed = store.destroyObject(handle);
    EXPECT_TRUE(destroyed);

    // After destruction, getObject should return nullptr
    HsmObject* retrieved = store.getObject(handle);
    EXPECT_EQ(retrieved, nullptr);

    // Handle should now be invalid
    EXPECT_FALSE(store.isValidHandle(handle));
}

TEST(ObjectStore, GetObjectCount) {
    ObjectStore store;
    EXPECT_EQ(store.getObjectCount(), 0u);

    auto [handle1, obj1] = store.createObject<HsmObject>(ObjectType::SECRET_KEY);
    EXPECT_EQ(store.getObjectCount(), 1u);

    auto [handle2, obj2] = store.createObject<HsmObject>(ObjectType::PUBLIC_KEY);
    EXPECT_EQ(store.getObjectCount(), 2u);

    // Destroy one object
    store.destroyObject(handle1);
    EXPECT_EQ(store.getObjectCount(), 1u);

    // Destroy the other
    store.destroyObject(handle2);
    EXPECT_EQ(store.getObjectCount(), 0u);
}

TEST(ObjectStore, IsValidHandle) {
    ObjectStore store;

    // Invalid handle (0) should be invalid
    EXPECT_FALSE(store.isValidHandle(CK_INVALID_HANDLE));

    auto [handle, objPtr] = store.createObject<HsmObject>(ObjectType::SECRET_KEY);
    EXPECT_TRUE(store.isValidHandle(handle));

    // Destroy the object
    store.destroyObject(handle);
    EXPECT_FALSE(store.isValidHandle(handle));
}

TEST(ObjectStore, CreateObjectWithArgs) {
    ObjectStore store;

    // Create an object with sensitive=true, extractable=false
    auto [handle, objPtr] = store.createObject<HsmObject>(ObjectType::SECRET_KEY, true, false);
    EXPECT_NE(handle, CK_INVALID_HANDLE);

    HsmObject* retrieved = store.getObject(handle);
    EXPECT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved->getType(), ObjectType::SECRET_KEY);
    EXPECT_TRUE(retrieved->isSensitive());
    EXPECT_FALSE(retrieved->isExtractable());
}