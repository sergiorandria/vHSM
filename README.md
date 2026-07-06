# Virtual HSM (vHSM)

A virtual Hardware Security Module (HSM) implementation that provides PKCS#11 interface and REST API for cryptographic operations, backed by Hyperledger Fabric for secure audit logging and key management.

## Architecture

The vHSM consists of several components:

```
┌─────────────────────┐
│ Jury Application    │
│ (Web/Desktop UI)    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Go Backend API      │
│ (Gin/Fiber)         │
└──────────┬──────────┘
           │
           ├─────────────────┐
           │                 │
           ▼                 ▼
┌─────────────────┐   ┌─────────────────┐
│ SoftHSM         │   │ Document Store  │
│ PKCS#11         │   │ Thesis PDFs     │
└────────┬────────┘   └────────┬────────┘
         │                     │
         ▼                     ▼
    Digital Signature      SHA256 Hash
         │                     │
         └──────────┬──────────┘
                    ▼
          ┌───────────────────┐
          │ Fabric Gateway    │
          │ Go SDK            │
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Hyperledger Fabric│
          │ Chaincode         │
          └─────────┬─────────┘
                    ▼
          ┌───────────────────┐
          │ Distributed Ledger│
          └───────────────────┘
```

## Getting Started

### Prerequisites

- CMake 3.21 or higher
- C++23 compiler (GCC, Clang, or MSVC)
- OpenSSL
- gRPC (if VHSM_ADMIN_GRPC is enabled)
- Protobuf
- Database backend (SQLite3, PostgreSQL, or MySQL)
- libcurl (for email/webhook notifications)
- nlohmann_json (3.11.0 or higher)
- Go 1.19+ (for the REST API)
- Docker and Docker Compose (for Hyperledger Fabric tests)

### Building

```bash
mkdir build && cd build
cmake .. -G "Ninja"  # or your preferred generator
cmake --build .
```

#### CMake Options

- `VHSM_DB_BACKEND`: Database backend (`sqlite`, `postgres`, `mysql`) (default: `sqlite`)
- `VHSM_ASYNC_DB`: Use async write queue for DB (default: `OFF`)
- `VHSM_REQUIRE_DB`: Fail C_Sign if DB write fails (default: `ON`)
- `VHSM_ADMIN_GRPC`: Build gRPC admin server (default: `ON`)
- `VHSM_NOTIFY_EMAIL`: Build email notification adapter (default: `ON`)
- `VHSM_NOTIFY_WEBHOOK`: Build webhook notification adapter (default: `ON`)
- `VHSM_NOTIFY_BUS_SIZE`: Notification ring buffer capacity (default: `1024`)

Example:
```bash
cmake .. -DVHSM_DB_BACKEND=postgres -DVHSM_NOTIFY_EMAIL=ON
```

### Running the REST API

The REST API is located in the `rest_api` directory.

1. Install dependencies:
   ```bash
   cd rest_api
   go mod download
   ```

2. Run the installation script to set up environment variables and configuration:
   ```bash
   ./install.sh
   ```

3. Copy the service file and adjust paths as needed:
   ```bash
   sudo cp vhsm.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl start vhsm
   ```

4. The API will be available at `http://localhost:8080` (default port).

### Running Tests

#### Unit Tests

```bash
cd build
ctest  # or run the individual test executables
```

#### REST API Tests

See [tests/rest_api/README.md](tests/rest_api/README.md) for detailed instructions on running the REST API tests, which require a running Hyperledger Fabric network.

## Configuration

Configuration files are located in `/etc/vhsm/` after installation.

Key configuration files:
- `vhsm.conf`: Main configuration file
- Email/webhook adapter configurations (if enabled)

## Documentation

- [REST API Documentation](rest_api/README.md)
- [Project Plan](plan/)
- [Source Code Structure](src/)

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Acknowledgments

- Hyperledger Fabric for blockchain infrastructure
- SoftHSM for PKCS#11 reference implementation