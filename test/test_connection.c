/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <my_sys.h>
#include <mysql.h>
#include <common.h>
#include <audit.h>
#include <audit_file.h>
#include <audit_table.h>
#include "check_result.h"
#include "db_util.h"
#include "util.h"

char audit_datetime[DATE_LEN]={0};
char audit_name[FILE_NAME_LEN]={0};

my_bool check_connect(uint audit_class,MYSQL* mysql, char* host,char*user,char*password,char* database,uint port,char* sock,ulong flag)
{
  char* pfile,*pdate;
  mysql_init(mysql);  
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;  
    if(!open_connection( mysql, host,user,password, database, port, sock,flag))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_CONNECT_NAME.str,user,host);
  }
  else{
    opt_audit_class = 4;
    if(!open_connection( mysql, host,user,password, database, port, sock,flag))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_CONNECT_NAME.str,"user",user,"host",host);
  }
}

my_bool check_quit(uint audit_class,MYSQL* mysql)
{
  char* pname,*pdate;
  char user[FN_LEN] = {0};
  char host[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(user,mysql->user,FN_LEN);
  strmake(host,mysql->host,FN_LEN);

  pdate = get_current_datetime(audit_datetime); 

  if(audit_class==2)
  {
    opt_audit_class = 2;
    close_connection(mysql);
    pname = get_audit_file_name(audit_name,FILE_NAME_LEN);    
    return check_file_result(pname,pdate,AUDIT_QUIT_NAME.str,user,host);
  }
  else{
    opt_audit_class = 4;
    close_connection(mysql);
    pname = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pname,pdate,"command",AUDIT_QUIT_NAME.str,"user",user,"host",host);
  }
}

my_bool check_change_user(uint audit_class,MYSQL* mysql,char* user, char* password,char* db)
{
  char* pname,*pdate;
  char host[FN_LEN] = {0};
  strmake(host,mysql->host,FN_LEN);
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime); 

  if(audit_class==2)
  {
    opt_audit_class = 2;
    if(!mysql_change_user(mysql,user,password,db))
      return FALSE;
    pname = get_audit_file_name(audit_name,FILE_NAME_LEN); 
    return check_file_result(pname,pdate,AUDIT_CHANGE_USER_NAME.str,user,host);
  }
  else{
    opt_audit_class = 4;
    if(!mysql_change_user(mysql,user,password,db))
      return FALSE;
    pname = get_audit_table_name(audit_name,FILE_NAME_LEN);   
    return check_table_result(pname,pdate,"command",AUDIT_CHANGE_USER_NAME.str,"user",user,"host",host);
  }
}

int main(int argc, char* argv[])
{
  char* host="localhost";
  char* user="audit";
  char* password="";
  char* database="audit";
  char* sock="/tmp/mysql.sock";
  uint port=3306;

  char* change_user = "audit";
  char* change_password = "";
  char* change_database = "test";

  MYSQL* mysql;  
  my_bool flag = TRUE;
  ulonglong origin_audit_ops = opt_audit_ops;
  uint origin_audit_class = opt_audit_class;
  static int success = 0;
  static int failed = 0;

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_CONNECTION;

  flag = check_connect(2,mysql,host,user,password,database,port,sock,0);
  printf("Audit the connection into file\n");
  if(flag)
  {
    success++;
    printf("Connect: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Connect: FAILED!\n");
  }

  flag = check_change_user(2,mysql,change_user,change_password,change_database);
  printf("Audit the change user into file\n");
  if(flag)
  {
    success++;
    printf("Change_user: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Change_user: FAILED!\n");
  }  

  flag = check_quit(2,mysql);
  printf("Audit the quit into file\n");
  if(flag)
  {
    success++;
    printf("Quit: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Quit: FAILED!\n");
  } 

  opt_audit_class = 4;
  flag = check_connect(4,mysql,host,user,password,database,port,sock,0);
  printf("Audit the connection into table\n");
  if(flag)
  {
    success++;
    printf("Connect: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Connect: FAILED!\n");
  }

  flag = check_change_user(4,mysql,change_user,change_password,change_database);
  printf("Audit the change user into table\n");
  if(flag)
  {
    success++;
    printf("Change_user: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Change_user: FAILED!\n");
  } 

  flag = check_quit(4,mysql);
  printf("Audit the quit into table\n");
  if(flag)
  {
    success++;
    printf("Quit: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Quit: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_CONNECTION;
  flag = check_connect(2,mysql,host,user,password,database,port,sock,0);
  printf("Don't audit the connection into file\n");
  if(!flag)
  {
    success++;
    printf("Connect: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Connect: FAILED!\n");
  }

  flag = check_change_user(2,mysql,change_user,change_password,change_database);
  printf("Don't audit the change user into file\n");
  if(!flag)
  {
    success++;
    printf("Change_user: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Change_user: FAILED!\n");
  }  

  flag = check_quit(2,mysql);
  printf("Don't audit the quit into file\n");
  if(!flag)
  {
    success++;
    printf("Quit: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Quit: FAILED!\n");
  } 

  opt_audit_class = 4;
  flag = check_connect(4,mysql,host,user,password,database,port,sock,0);
  printf("Don't audit the connection into table\n");
  if(!flag)
  {
    success++;
    printf("Connect: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Connect: FAILED!\n");
  }

  flag = check_change_user(4,mysql,change_user,change_password,change_database);
  printf("Don't audit the change user into table\n");
  if(!flag)
  {
    success++;
    printf("Change_user: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Change_user: FAILED!\n");
  } 

  flag = check_quit(4,mysql);
  printf("Don't audit the quit into table\n");
  if(!flag)
  {
    success++;
    printf("Quit: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Quit: FAILED!\n");
  }

  opt_audit_class = origin_audit_class;
  opt_audit_ops =origin_audit_ops;

  printf("=============================\n");
  printf("total: %d, success: %d, failed: %d\n",success+failed,success,failed);
  return 0;   
}


