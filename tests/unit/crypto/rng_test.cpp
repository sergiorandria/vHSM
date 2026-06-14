#include <gtest/gtest.h>
#include <cstdint>
#include <cstddef>
#include <thread>

#include "../../../src/crypto/SecureRNG.h"

// Test Fixture for organizing vHSM RNG tests
class SecureRNGTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Code executed before each individual test runs (if needed)
    }

    void TearDown() override {
        // Code executed after each individual test runs (if needed)
    }
};

// 1. Test: Verifies successful initialization and non-zero execution
TEST_F(SecureRNGTest, InitializationAndBasicGeneration) {
    vHSM::SecureRNG rng;
    uint8_t buffer[32] = {0};

    // Populate buffer
    rng.bytes(buffer, sizeof(buffer));

    // Ensure the buffer is no longer completely zeroed out
    bool is_all_zero = true;
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        if (buffer[i] != 0) {
            is_all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(is_all_zero);
}

// 2. Test: Verifies that consecutive generations produce completely unique arrays
TEST_F(SecureRNGTest, UniquenessOfConsecutiveOutputs) {
    vHSM::SecureRNG rng;
    uint8_t run_a[16] = {0};
    uint8_t run_b[16] = {0};

    rng.bytes(run_a, sizeof(run_a));
    rng.bytes(run_b, sizeof(run_b));

    // Check how many bytes match exactly across the arrays
    int structural_matches = 0;
    for (size_t i = 0; i < sizeof(run_a); ++i) {
        if (run_a[i] == run_b[i]) {
            structural_matches++;
        }
    }

    // Over 16 bytes, a perfect matching array has a statistical probability near zero
    EXPECT_LT(structural_matches, sizeof(run_a));
}

// 3. Test: Verifies that the public API safely handles boundary constraints
TEST_F(SecureRNGTest, RobustnessToNullOrZeroInputs) {
    vHSM::SecureRNG rng;
    uint8_t* null_ptr = nullptr;

    // These calls should return instantly without throwing or causing a segmentation fault
    EXPECT_NO_THROW(rng.bytes(null_ptr, 100));
    EXPECT_NO_THROW(rng.bytes(nullptr, 0));
}

// 4. Test: Concurrency Stress-testing multiple vCPU loops simultaneously
TEST_F(SecureRNGTest, MultithreadedThreadSafety) {
    vHSM::SecureRNG rng;
    const int num_threads = 8;
    const int requests_per_thread = 500;
    
    std::vector<std::thread> workers;

    auto worker_task = [&rng, requests_per_thread]() {
        for (int i = 0; i < requests_per_thread; ++i) {
            uint8_t token[24] = {0}; // Initialize to all zeros
            rng.bytes(token, sizeof(token));
            
            // PROPER CHECK: Verify the token was actually populated 
            // by ensuring it's no longer a block of pure zeros.
            bool modified = false;
            for (size_t j = 0; j < sizeof(token); ++j) {
                if (token[j] != 0) {
                    modified = true;
                    break;
                }
            }
            EXPECT_TRUE(modified); 
        }
    };

    // Spin up concurrent worker threads hitting the single mutex lock
    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back(worker_task);
    }

    // Join threads and check for deadlocks
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

// 5. Test: Administrative explicit state rotation execution path
TEST_F(SecureRNGTest, ForceReseedExecutionPath) {
    vHSM::SecureRNG rng;
    EXPECT_NO_THROW(rng.force_reseed());
    
    uint8_t post_reseed_buffer[16];
    EXPECT_NO_THROW(rng.bytes(post_reseed_buffer, sizeof(post_reseed_buffer)));
}

// Global entry point configured by GTest
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}