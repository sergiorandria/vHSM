add_library(vhsm_core
    secure_buffer.cpp
    utils.cpp
    frozen_hsm_clock.cpp
    system_hsm_clock.cpp
    hsm_instance.cpp
)

if(WIN32)
    target_link_libraries(vhsm_core PRIVATE bcrypt)
endif()