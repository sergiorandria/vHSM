#include <iostream>
#include "../include/fabric/ca/ca_client.h"
#include "../include/fabric/ca/httpclient.h"

int main() {
    std::cout << "Testing CA Client instantiation..." << std::endl;
    auto httpClient = std::make_shared<fabric::ca::CurlHttpClient>();
    fabric::ca::CaClient caClient(httpClient, "http://localhost:7054");
    std::cout << "CA Client created successfully!" << std::endl;
    return 0;
}
