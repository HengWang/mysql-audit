# Copyright (c) 2012, Heng.Wang. All rights reserved.

# This program is aimed to audit the mysql database operations. 
# If you have the more efficient method to audit the mysql database,
# thanks for your sharing with the developers. It's pleasure for you
#to contact me heng.wang@qunar.com  

INCLUDE_DIRECTORIES(
${CMAKE_SOURCE_DIR}
${CMAKE_SOURCE_DIR}/include
${CMAKE_SOURCE_DIR}/plugin/mysql-audit/include
)

ADD_DEFINITIONS(-DMYSQL_SERVER)

#ADD_SUBDIRECTORY(test)

MYSQL_ADD_PLUGIN(audit include/audit.h audit.cc include/common.h common.c audit_config.h audit_config.c
include/audit_file.h file/audit_file.cc include/audit_table.h table/audit_table.cc
  MODULE_ONLY MODULE_OUTPUT_NAME "audit")

SET(AUDIT_CONFIG_DIR ${CMAKE_INSTALL_PREFIX}/lib/plugin/)

IF(WIN32) 
  INSTALL(FILES etc/audit.ini DESTINATION ${AUDIT_CONFIG_DIR})
ELSE(WIN32)
  INSTALL(FILES etc/audit.cnf DESTINATION ${AUDIT_CONFIG_DIR})
ENDIF(WIN32)

#SET(AUDIT_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include/audit)
#INSTALL(DIRECTORY include/ DESTINATION ${AUDIT_INCLUDE_DIR})

#SET(AUDIT_TEST_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include/audit/test)
#INSTALL(FILES test/db_util.h test/util.h test/check_result.h test/test_connection.h test/test_dml.h test/test_ddl.h test/test_dcl.h test/test_password.h test/test_server.h  DESTINATION ${AUDIT_TEST_INCLUDE_DIR})

#SET(AUDIT_TEST_BIN_DIR ${CMAKE_INSTALL_PREFIX}/mysql-test/audit)
#INSTALL(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin/ DESTINATION ${AUDIT_TEST_BIN_DIR})


