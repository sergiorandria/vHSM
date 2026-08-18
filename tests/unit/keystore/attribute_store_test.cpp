#include <gtest/gtest.h>

#include "../../../src/keystore/attribute_store.h"
#include "../../../src/keystore/hsm_object.h"

using namespace vhsm::keystore;
using namespace vhsm::keystore::internal;

TEST(v_AttributeStore_M1, SetAndGetLabel) {
    HsmObject obj(ObjectType::SECRET_KEY);
    v_AttributeStore_M1 store(obj);

    const char* label = "test-label";
    CK_ATTRIBUTE attr = {CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label)};

    CK_RV rv = store.v_set_attribute(&attr);
    EXPECT_EQ(rv, CKR_OK);

    CK_ULONG len = 0;
    rv = store.v_get_attribute(CKA_LABEL, nullptr, &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)strlen(label));

    std::vector<unsigned char> value(len);
    rv = store.v_get_attribute(CKA_LABEL, value.data(), &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)strlen(label));
    EXPECT_STREQ((char*)value.data(), label);
}

TEST(v_AttributeStore_M1, SetAndGetValue) {
    HsmObject obj(ObjectType::SECRET_KEY);
    v_AttributeStore_M1 store(obj);

    std::vector<unsigned char> keyValue = {0x01, 0x02, 0x03, 0x04};
    CK_ATTRIBUTE attr = {CKA_VALUE, keyValue.data(), (CK_ULONG)keyValue.size()};

    CK_RV rv = store.v_set_attribute(&attr);
    EXPECT_EQ(rv, CKR_OK);

    CK_ULONG len = 0;
    rv = store.v_get_attribute(CKA_VALUE, nullptr, &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)keyValue.size());

    std::vector<unsigned char> value(len);
    rv = store.v_get_attribute(CKA_VALUE, value.data(), &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)keyValue.size());
    EXPECT_EQ(value, keyValue);
}

TEST(v_AttributeStore_M1, ReadOnlyAttributesAfterInit) {
    HsmObject obj(ObjectType::SECRET_KEY);
    v_AttributeStore_M1 store(obj);

    store.v_initialize_default_attributes();

    CK_BBOOL tokenFalse = CK_FALSE;
    CK_ATTRIBUTE tokenAttr = {CKA_TOKEN, &tokenFalse, sizeof(tokenFalse)};
    CK_RV rv = store.v_set_attribute(&tokenAttr);
    EXPECT_NE(rv, CKR_OK);

    CK_BBOOL privFalse = CK_FALSE;
    CK_ATTRIBUTE privAttr = {CKA_PRIVATE, &privFalse, sizeof(privFalse)};
    rv = store.v_set_attribute(&privAttr);
    EXPECT_NE(rv, CKR_OK);
}
