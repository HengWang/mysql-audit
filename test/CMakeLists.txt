# Copyright (c) 2012, Heng.Wang. All rights reserved.

# This program is aimed to audit the mysql database operations. 
# If you have the more efficient method to audit the mysql database,
# thanks for your sharing with the developers. It's pleasure for you
# to contact me king_wangheng@163.com

project(audit_test)

INCLUDE_DIRECTORIES(
${CMAKE_SOURCE_DIR}
${CMAKE_SOURCE_DIR}/include
${CMAKE_SOURCE_DIR}/plugin/mysql-audit/include
)

SET(BIN_DIR ../bin)
SET(EXECUTABLE_OUTPUT_PATH ${BIN_DIR})

SET(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)

ADD_EXECUTABLE(audit_test main.c check_result.c db_util.c  util.c)
ADD_EXECUTABLE(audit_test_connection test_connection.c check_result.c db_util.c  util.c)
ADD_EXECUTABLE(audit_test_dml test_dml.c check_result.c db_util.c  util.c)
ADD_EXECUTABLE(audit_test_ddl test_ddl.c check_result.c db_util.c  util.c)
ADD_EXECUTABLE(audit_test_dcl test_dcl.c check_result.c db_util.c  util.c)
ADD_EXECUTABLE(audit_test_server test_server.c check_result.c db_util.c  util.c)
ADD_EXECUTABLE(audit_test_password test_password.c check_result.c db_util.c util.c)


IF(WIN32) 
  TARGET_LINK_LIBRARIES(audit_test mysqlclient.lib audit.lib)
  TARGET_LINK_LIBRARIES(audit_test_connection mysqlclient.lib audit.lib)
  TARGET_LINK_LIBRARIES(audit_test_dml mysqlclient.lib audit.lib)
  TARGET_LINK_LIBRARIES(audit_test_ddl mysqlclient.lib audit.lib)
  TARGET_LINK_LIBRARIES(audit_test_dcl mysqlclient.lib audit.lib)
  TARGET_LINK_LIBRARIES(audit_test_server mysqlclient.lib audit.lib)
  TARGET_LINK_LIBRARIES(audit_test_password mysqlclient.lib audit.lib)
ELSE(WIN32) 
  TARGET_LINK_LIBRARIES(audit_test mysqlclient audit)
  TARGET_LINK_LIBRARIES(audit_test_connection mysqlclient audit)
  TARGET_LINK_LIBRARIES(audit_test_dml mysqlclient audit)
  TARGET_LINK_LIBRARIES(audit_test_ddl mysqlclient audit)
  TARGET_LINK_LIBRARIES(audit_test_dcl mysqlclient audit)
  TARGET_LINK_LIBRARIES(audit_test_server mysqlclient audit)
  TARGET_LINK_LIBRARIES(audit_test_password mysqlclient audit)
ENDIF(WIN32)

ADD_DEPENDENCIES(audit_test mysqlclient audit)
ADD_DEPENDENCIES(audit_test_connection mysqlclient audit)
ADD_DEPENDENCIES(audit_test_dml mysqlclient audit)
ADD_DEPENDENCIES(audit_test_ddl mysqlclient audit)
ADD_DEPENDENCIES(audit_test_dcl mysqlclient audit)
ADD_DEPENDENCIES(audit_test_server mysqlclient audit)
ADD_DEPENDENCIES(audit_test_password mysqlclient audit)



