# Tests
enable_testing()

# Unit tests
add_subdirectory(unit)

# Integration tests (commented out for now - requires additional setup)
# add_subdirectory(integration)

# Conformance tests (commented out for now - requires OASIS PKCS#11 suite)
# add_subdirectory(conformance)

# Fuzz tests (commented out for now - requires libFuzzer)
# add_subdirectory(fuzz)