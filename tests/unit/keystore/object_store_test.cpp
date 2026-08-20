#include <gtest/gtest.h>

#include "../../../src/keystore/object_store.h"

using namespace vhsm::keystore;
using namespace vhsm::keystore::internal;

TEST(v_ObjectStore_M1, CreateAndGetObject) {
  v_ObjectStore_M1 store;

  auto [handle, objPtr] =
      store.v_create_object<HsmObject>(ObjectType::SECRET_KEY);
  EXPECT_NE(handle, CK_INVALID_HANDLE);
  EXPECT_NE(objPtr, nullptr);

  auto retrieved = store.v_get_object(handle);
  EXPECT_EQ(retrieved, objPtr);
  EXPECT_NE(retrieved, nullptr);

  EXPECT_EQ(retrieved->getType(), ObjectType::SECRET_KEY);
}

TEST(v_ObjectStore_M1, DestroyObject) {
  v_ObjectStore_M1 store;

  auto [handle, objPtr] =
      store.v_create_object<HsmObject>(ObjectType::SECRET_KEY);
  EXPECT_NE(handle, CK_INVALID_HANDLE);

  bool destroyed = store.v_destroy_object(handle);
  EXPECT_TRUE(destroyed);

  auto retrieved = store.v_get_object(handle);
  EXPECT_EQ(retrieved, nullptr);

  EXPECT_FALSE(store.v_is_valid_handle(handle));
}

TEST(v_ObjectStore_M1, GetObjectCount) {
  v_ObjectStore_M1 store;
  EXPECT_EQ(store.v_get_object_count(), 0u);

  auto [handle1, obj1] =
      store.v_create_object<HsmObject>(ObjectType::SECRET_KEY);
  EXPECT_EQ(store.v_get_object_count(), 1u);

  auto [handle2, obj2] =
      store.v_create_object<HsmObject>(ObjectType::PUBLIC_KEY);
  EXPECT_EQ(store.v_get_object_count(), 2u);

  store.v_destroy_object(handle1);
  EXPECT_EQ(store.v_get_object_count(), 1u);

  store.v_destroy_object(handle2);
  EXPECT_EQ(store.v_get_object_count(), 0u);
}

TEST(v_ObjectStore_M1, IsValidHandle) {
  v_ObjectStore_M1 store;

  EXPECT_FALSE(store.v_is_valid_handle(CK_INVALID_HANDLE));

  auto [handle, objPtr] =
      store.v_create_object<HsmObject>(ObjectType::SECRET_KEY);
  EXPECT_TRUE(store.v_is_valid_handle(handle));

  store.v_destroy_object(handle);
  EXPECT_FALSE(store.v_is_valid_handle(handle));
}

TEST(v_ObjectStore_M1, CreateObjectWithArgs) {
  v_ObjectStore_M1 store;

  auto [handle, objPtr] =
      store.v_create_object<HsmObject>(ObjectType::SECRET_KEY, true, false);
  EXPECT_NE(handle, CK_INVALID_HANDLE);

  auto retrieved = store.v_get_object(handle);
  EXPECT_NE(retrieved, nullptr);
  EXPECT_EQ(retrieved->getType(), ObjectType::SECRET_KEY);
  EXPECT_TRUE(retrieved->isSensitive());
  EXPECT_FALSE(retrieved->isExtractable());
}
