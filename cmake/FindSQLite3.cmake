# - Find SQLite3
# This module defines:
#  SQLite3_FOUND
#  SQLite3_INCLUDE_DIRS
#  SQLite3_LIBRARIES

find_package(SQLite3 QUIET)
if(SQLITE3_FOUND)
    set(SQLite3_FOUND TRUE)
    set(SQLite3_INCLUDE_DIRS ${SQLITE3_INCLUDE_DIR})
    set(SQLite3_LIBRARIES ${SQLITE3_LIBRARY})
else()
    set(SQLite3_FOUND FALSE)
endif()
mark_as_advanced(SQLite3_INCLUDE_DIRS SQLite3_LIBRARIES)