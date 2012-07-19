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
#include "db_util.h"
#include "util.h"

char audit_datetime[DATE_LEN]={0};
char audit_name[FILE_NAME_LEN]={0};

my_bool check_password_insert_mysql_user_with_col(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"INSERT INTO MYSQL.USER (HOST,USER, PASSWORD) values('localhost','test_insert_mysql_user','aaa')",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO MYSQL.USER (HOST,USER, PASSWORD) values('localhost','test_insert_mysql_user','###')",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_INSERT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO MYSQL.USER (HOST,USER, PASSWORD) values('localhost','test_insert_mysql_user','###')",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_INSERT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_password_insert_user_with_col(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  if(!execute_no_query(mysql,"USE MYSQL"))
    return FALSE;
  strmake(sql,"INSERT INTO USER (HOST,USER, PASSWORD) values('localhost','test_insert_user','aaa')",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO USER (HOST,USER, PASSWORD) values('localhost','test_insert_user','###')",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_INSERT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO USER (HOST,USER, PASSWORD) values('localhost','test_insert_user','###')",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_INSERT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_password_insert_mysql_user_without_col(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;

  strmake(sql,"INSERT INTO MYSQL.USER values('localhost','test_insert_mysql_user_1','aaa','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','','','','',0,0,0,0,'','')",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO MYSQL.USER values('localhost','test_insert_mysql_user_1','###','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','','','','',0,0,0,0,'','')",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_INSERT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO MYSQL.USER values('localhost','test_insert_mysql_user_1','###','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','','','','',0,0,0,0,'','')",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_INSERT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_password_insert_user_without_col(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  if(!execute_no_query(mysql,"USE MYSQL"))
    return FALSE;
  strmake(sql,"INSERT INTO USER values('localhost','test_insert_user_1','aaa','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','','','','',0,0,0,0,'','')",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO USER values('localhost','test_insert_user_1','###','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','','','','',0,0,0,0,'','')",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_INSERT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"INSERT INTO USER values('localhost','test_insert_user_1','###','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','','','','',0,0,0,0,'','')",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_INSERT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_password_update_mysql_user(uint audit_class, MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"UPDATE MYSQL.USER SET PASSWORD=PASSWORD('aaa') WHERE USER LIKE 'test%'",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"UPDATE MYSQL.USER SET PASSWORD=PASSWORD('###') WHERE USER LIKE 'test%'",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_UPDATE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"UPDATE MYSQL.USER SET PASSWORD=PASSWORD('###') WHERE USER LIKE 'test%'",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_UPDATE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_password_update_user(uint audit_class, MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  if(!execute_no_query(mysql,"USE MYSQL"))
    return FALSE;
  strmake(sql,"UPDATE USER SET PASSWORD=PASSWORD('aaa') WHERE USER LIKE 'test%'",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"UPDATE USER SET PASSWORD=PASSWORD('###') WHERE USER LIKE 'test%'",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_UPDATE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"UPDATE USER SET PASSWORD=PASSWORD('###') WHERE USER LIKE 'test%'",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_UPDATE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_password_set(uint audit_class, MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"SET PASSWORD FOR 'test_insert_user'@'localhost' = PASSWORD('ccc')",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"SET PASSWORD FOR 'test_insert_user'@'localhost' = PASSWORD('###')",FN_LEN);
    return check_file_result(pfile,pdate,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"SET PASSWORD FOR 'test_insert_user'@'localhost' = PASSWORD('###')",FN_LEN);
    return check_table_result(pfile,pdate,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}
my_bool check_password_grant(uint audit_class, MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"GRANT ALL ON *.* TO 'test'@'localhost' IDENTIFIED BY 'aaa'",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"GRANT ALL ON *.* TO 'test'@'localhost' IDENTIFIED BY '###'",FN_LEN);
    return check_file_result(pfile,pdate,AUDIT_GRANT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    strmake(sql,"GRANT ALL ON *.* TO 'test'@'localhost' IDENTIFIED BY '###'",FN_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_GRANT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

int main(int argc,char* argv[])
{
  char* host="localhost";
  char* user="audit";
  char* password="";
  char* database="audit";
  char* sock="/tmp/mysql.sock";
  uint port=3306;

  MYSQL* mysql;  
  my_bool flag = TRUE;
  char sql[FN_LEN] = {0};
  char* table="test";

  ulonglong origin_audit_ops = opt_audit_ops;
  static int success = 0;
  static int failed = 0;

  opt_audit_ops = 0;

  mysql_init(mysql);  
  if(!open_connection( mysql, host,user,password, database, port, sock,0))
  {
    printf("Error: Connection failed when testing the dml operation for audit\n");
    return FALSE;
  }

  opt_audit_ops |=AUDIT_DML;

  flag = check_password_insert_mysql_user_with_col(2,mysql);
  printf("Audit the earsed the password of inserting mysql user operation into file\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Password: FAILED!\n");
  }

  flag = check_password_insert_user_with_col(2,mysql);
  printf("Audit the earsed the password of inserting user operation into file\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  }  

  flag = check_password_insert_mysql_user_without_col(2,mysql);
  printf("Audit the earsed the password of inserting mysql user without column operation file\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_insert_user_without_col(2,mysql);
  printf("Audit the earsed the password of inserting user without column operation file\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_update_mysql_user(2,mysql);
  printf("Audit the earsed the password of updating mysql user operation file\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_update_user(2,mysql);
  printf("Audit the earsed the password of updating user operation file\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_insert_mysql_user_with_col(4,mysql);
  printf("Audit the earsed the password of inserting mysql user operation into table\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Password: FAILED!\n");
  }

  flag = check_password_insert_user_with_col(4,mysql);
  printf("Audit the earsed the password of inserting user operation into table\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  }  

  flag = check_password_insert_mysql_user_without_col(4,mysql);
  printf("Audit the earsed the password of inserting mysql user without column operation table\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_insert_user_without_col(4,mysql);
  printf("Audit the earsed the password of inserting user without column operation table\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_update_mysql_user(4,mysql);
  printf("Audit the earsed the password of updating mysql user operation table\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  } 

  flag = check_password_update_user(4,mysql);
  printf("Audit the earsed the password of updating user operation table\n");
  if(flag)
  {
    success++;
    printf("Password: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Password: FAILED!\n");
  }   

  close_connection(mysql);

  opt_audit_ops =origin_audit_ops;
  printf("=============================\n");
  printf("total: %d, success: %d, failed: %d\n",success+failed,success,failed);
  return 0;   

}
