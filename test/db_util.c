/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/
#include <my_global.h>
#include <mysql.h>

MYSQL* open_connection(MYSQL* mysql, char* host,char*user,char*password,char* database,uint port,char* sock,ulong flag)
{
  MYSQL* handle;
  if(!mysql || !host || !user || !password || !database || !sock)
    return NULL;
  if (!(handle = mysql_real_connect(mysql,host,user,password,database,port,NULL,0))) {
    fprintf(stderr,"Couldn't connect to engine!\n%s\n\n",mysql_error(mysql)); 
  }
  return handle;
}

int execute_no_query(MYSQL* mysql, char* sql)
{
  if(mysql_query(mysql,sql)){
    fprintf(stderr,"Query failed (%s)\n",mysql_error(mysql)); 
    return 1;
  }
  return 0;
}

MYSQL_RES * execute_query(MYSQL *mysql, char* sql)
{
  MYSQL_RES *result;
  if(mysql_query(mysql,sql)){
    fprintf(stderr,"Query failed (%s)\n",mysql_error(mysql)); 
    return NULL;
  }
  if(!(result=mysql_store_result(mysql))){
    fprintf(stderr,"Couldn't get result from %s\n", mysql_error(mysql));
    return NULL;
  }
  return result;
}

void close_connection(MYSQL* handle)
{
  if(handle)
    mysql_close(handle);  
}

