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

The repository ships CMake presets (see `CMakePresets.json`) — prefer them over
hand-rolled `cmake` invocations:

```bash
cmake --preset linux-ninja     # RelWithDebInfo, Ninja, sqlite, no gRPC/ledger
cmake --build build -j         # parallel build
ctest --test-dir build -j      # run all 271 unit tests
```

Available presets:

| Preset        | Build dir      | Purpose                                        |
| ------------- | -------------- | ---------------------------------------------- |
| `linux-ninja` | `build/`       | Default Linux development build (RelWithDebInfo) |
| `release`     | `build-release/` | Optimized `-O3` + LTO production build       |
| `windows-msvc`| `build/`       | Windows MSVC via vcpkg manifest                |
| `asan`        | `build-asan/`  | ASan + UBSan instrumented build                |

Manual configuration (without presets) works as well:

```bash
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

If no `CMAKE_BUILD_TYPE` is given, the project defaults to `RelWithDebInfo`.
When `ccache` is installed it is picked up automatically as compiler launcher.

#### Build Performance Options

- `VHSM_ENABLE_IPO`: Interprocedural optimization / LTO for Release,
  RelWithDebInfo and MinSizeRel (default: auto-detected; ON when the
  toolchain supports it). Debug builds stay LTO-free so debuggers and
  sanitizers behave predictably.
- `VHSM_UNITY_BUILD`: Unity build — concatenates sources per target for much
  faster clean builds at the cost of slower incremental rebuilds
  (default: `OFF`; can collide with file-local symbols).
- `VHSM_LINKER`: Linker override (`default`, `bfd`, `lld`, `mold`;
  default: `default`). Only change this after verifying your compiler +
  linker combination supports LTO (e.g. lld is known-broken with GCC 16 LTO).

#### CMake Options

- `VHSM_DB_BACKEND`: Database backend (`sqlite`, `postgres`, `mysql`) (default: `sqlite`)
- `VHSM_ASYNC_DB`: Use async write queue for DB (default: `OFF`)
- `VHSM_REQUIRE_DB`: Fail C_Sign if DB write fails (default: `ON`)
- `VHSM_ADMIN_GRPC`: Build gRPC admin server (default: `ON`)
- `VHSM_NOTIFY_EMAIL`: Build email notification adapter (default: `ON`)
- `VHSM_NOTIFY_WEBHOOK`: Build webhook notification adapter (default: `ON`)
- `VHSM_NOTIFY_BUS_SIZE`: Notification ring buffer capacity (default: `1024`)
- `VHSM_STORE_BACKEND`: Signature store backend (`db`, `ledger`) (default: `db`; `ledger` forces `VHSM_LEDGER=ON`)
- `VHSM_LEDGER`: Build the Fabric ledger signature anchor integration (default: `ON`)
- `VHSM_USE_SECURE_CRYPTO`: Use hardened `vhsm-secure-crypto` clone instead of system OpenSSL for symmetric primitives (default: `ON`)

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
ctest --test-dir build -j   # parallel run of all unit tests
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