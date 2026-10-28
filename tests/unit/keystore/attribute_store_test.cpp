#include <gtest/gtest.h>

#include "../../../src/keystore/attribute_store.h"
#include "../../../src/keystore/hsm_object.h"

using namespace vhsm::keystore;
using namespace vhsm::keystore::internal;

TEST(v_AttributeStore_M1, SetAndGetLabel) {
  HsmObject obj(ObjectType::SECRET_KEY);
  v_AttributeStore_M1 store(obj);

  const char *label = "test-label";
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
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(value.data()),
                        value.size()),
            std::string(label));
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

TEST(v_AttributeStore_M1, SensitiveAndNonExtractableKeyMaterialIsNotReadable) {
  // Vendor private-key blobs must follow CKA_SENSITIVE/CKA_EXTRACTABLE just
  // like CKA_VALUE. These IDs mirror src/pkcs11/pkcs11_internal.h.
  constexpr CK_ATTRIBUTE_TYPE kRsaPriv = 0x81000001UL;
  constexpr CK_ATTRIBUTE_TYPE kEcPriv = 0x81000003UL;
  const std::vector<unsigned char> der = {0x30, 0x01, 0x02};

  for (CK_ATTRIBUTE_TYPE type : {kRsaPriv, kEcPriv, CKA_VALUE}) {
    HsmObject sensitive(ObjectType::PRIVATE_KEY, /*sensitive=*/true,
                        /*extractable=*/true);
    sensitive.setAttribute(type, der.data(), der.size());
    v_AttributeStore_M1 sensitiveStore(sensitive);
    CK_ULONG len = 0;
    EXPECT_EQ(sensitiveStore.v_get_attribute(type, nullptr, &len),
              CKR_ATTRIBUTE_SENSITIVE);

    HsmObject unextractable(ObjectType::PRIVATE_KEY, /*sensitive=*/false,
                            /*extractable=*/false);
    unextractable.setAttribute(type, der.data(), der.size());
    v_AttributeStore_M1 unextractableStore(unextractable);
    EXPECT_EQ(unextractableStore.v_get_attribute(type, nullptr, &len),
              CKR_ATTRIBUTE_SENSITIVE);
  }
}

TEST(v_AttributeStore_M1, PrivateKeyMaterialCannotBeOverwritten) {
  HsmObject obj(ObjectType::PRIVATE_KEY, /*sensitive=*/true,
                /*extractable=*/true);
  v_AttributeStore_M1 store(obj);
  std::vector<unsigned char> der = {0x30, 0x01, 0x02};

  for (CK_ATTRIBUTE_TYPE type : {0x81000001UL, 0x81000003UL, CKA_VALUE}) {
    CK_ATTRIBUTE attr = {type, der.data(), static_cast<CK_ULONG>(der.size())};
    EXPECT_EQ(store.v_set_attribute(&attr), CKR_ATTRIBUTE_READ_ONLY);
  }
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
