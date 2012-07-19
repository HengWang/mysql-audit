/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/
#include <my_global.h>
#include <mysql.h>

extern MYSQL* open_connection(MYSQL* mysql, char* host,char*user,char*password,char* database,uint port,char* sock,ulong flag);
extern int execute_no_query(MYSQL* mysql, char* sql);
extern MYSQL_RES * execute_query(MYSQL *mysql, char* sql);
extern void close_connection(MYSQL* handle);
