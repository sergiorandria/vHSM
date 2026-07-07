# - Find libcurl
# This module defines:
#  CURL_FOUND
#  CURL_INCLUDE_DIRS
#  CURL_LIBRARIES

find_package(CURL QUIET)
if(CURL_FOUND)
    set(CURL_FOUND TRUE)
    set(CURL_INCLUDE_DIRS ${CURL_INCLUDE_DIR})
    set(CURL_LIBRARIES ${CURL_LIBRARY})
else()
    set(CURL_FOUND FALSE)
endif()
mark_as_advanced(CURL_INCLUDE_DIRS CURL_LIBRARIES)