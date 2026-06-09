# - Find PostgreSQL (libpq)
# This module defines:
#  PostgreSQL_FOUND
#  PostgreSQL_INCLUDE_DIRS
#  PostgreSQL_LIBRARIES

find_package(PostgreSQL QUIET)
if(PostgreSQL_FOUND)
    set(PostgreSQL_FOUND TRUE)
    set(PostgreSQL_INCLUDE_DIRS ${PostgreSQL_INCLUDE_DIR})
    set(PostgreSQL_LIBRARIES ${PostgreSQL_LIBRARY})
else()
    set(PostgreSQL_FOUND FALSE)
endif()
mark_as_advanced(PostgreSQL_INCLUDE_DIRS PostgreSQL_LIBRARIES)