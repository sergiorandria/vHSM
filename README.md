##For Developers

mkdir build && cd build
cmake .. -G "Ninja"

(Adjust the generator as needed.) The options can be toggled when invoking CMake, e.g.:

cmake .. -DVHSM_DB_BACKEND=postgres -DVHSM_NOTIFY_EMAIL=ON