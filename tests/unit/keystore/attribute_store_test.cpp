#include <gtest/gtest.h>

#include "../../../src/keystore/attribute_store.h"
#include "../../../src/keystore/hsm_object.h"

using namespace vhsm::keystore;

TEST(AttributeStore, SetAndGetLabel) {
    HsmObject obj(ObjectType::SECRET_KEY);
    AttributeStore store(obj);

    const char* label = "test-label";
    CK_ATTRIBUTE attr = {CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label)};

    CK_RV rv = store.setAttribute(&attr);
    EXPECT_EQ(rv, CKR_OK);

    // Get the attribute value to verify
    CK_ULONG len = 0;
    rv = store.getAttribute(CKA_LABEL, nullptr, &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)strlen(label));

    std::vector<unsigned char> value(len);
    rv = store.getAttribute(CKA_LABEL, value.data(), &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)strlen(label));
    EXPECT_STREQ((char*)value.data(), label);
}

TEST(AttributeStore, SetAndGetValue) {
    HsmObject obj(ObjectType::SECRET_KEY);
    AttributeStore store(obj);

    std::vector<unsigned char> keyValue = {0x01, 0x02, 0x03, 0x04};
    CK_ATTRIBUTE attr = {CKA_VALUE, keyValue.data(), (CK_ULONG)keyValue.size()};

    CK_RV rv = store.setAttribute(&attr);
    EXPECT_EQ(rv, CKR_OK);

    // Get the attribute value to verify
    CK_ULONG len = 0;
    rv = store.getAttribute(CKA_VALUE, nullptr, &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)keyValue.size());

    std::vector<unsigned char> value(len);
    rv = store.getAttribute(CKA_VALUE, value.data(), &len);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_EQ(len, (CK_ULONG)keyValue.size());
    EXPECT_EQ(value, keyValue);
}

TEST(AttributeStore, ReadOnlyAttributesAfterInit) {
    HsmObject obj(ObjectType::SECRET_KEY);
    AttributeStore store(obj);

    // Initialize default attributes (sets CKA_CLASS and others)
    store.initializeDefaultAttributes();

    // Try to set CKA_TOKEN after initialization - should fail
    CK_BBOOL tokenFalse = CK_FALSE;
    CK_ATTRIBUTE tokenAttr = {CKA_TOKEN, &tokenFalse, sizeof(tokenFalse)};
    CK_RV rv = store.setAttribute(&tokenAttr);
    EXPECT_NE(rv, CKR_OK); // Expecting an error (likely CKR_ATTRIBUTE_READ_ONLY)

    // Try to set CKA_PRIVATE after initialization - should fail
    CK_BBOOL privFalse = CK_FALSE;
    CK_ATTRIBUTE privAttr = {CKA_PRIVATE, &privFalse, sizeof(privFalse)};
    rv = store.setAttribute(&privAttr);
    EXPECT_NE(rv, CKR_OK); // Expecting an error
}