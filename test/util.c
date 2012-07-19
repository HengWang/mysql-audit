/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/
#include <audit_file.h>
#include <audit_table.h>

char* get_audit_file_name(char* audit_file,uint len)
{
  return strmake(audit_file,audit_file_name,len-1);
}


char* get_audit_table_name(char* buffer, uint len)
{
  return strxnmov(buffer,len-1,MYSQL_SCHEMA_NAME.str, ".", AUDIT_NAME.str );
}

