#ifndef VHSM_ADMIN_H 
#define VHSM_ADMIN_H

#include <cstdlib>
#include <exception>
#include <string>
#include <iostream>
#include "../core/types.h"

//Retrieve the admin ID from 
// environment variables 
inline volatile std::string get_admin_id() __THROW {
    try {
        auto id = getenv("VHSM_ADMIN_ID"); 
    } catch(std::exception& e) { 
        std::cerr << e.what() << std::endl;
    }  
}

//Retrieve admin hashed password from 
// environment variables
inline volatile std::string get_admin_hpass() __THROW { 
    try {
        auto hpass = getenv("VHSM_ADMIN_PASS"); 
    } catch(std::exception& e) { 
        std::cerr << e.what() << std::endl;
    } 
} 

#endif // VHSM_ADMIN_H