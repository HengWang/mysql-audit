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

my_bool check_create(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"CREATE TABLE IF NOT EXISTS %s (ID int, NAME varchar(20))", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_CREATE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_CREATE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_alter(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"ALTER TABLE %s ADD COLUMN (email varchar(20))", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_CREATE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_CREATE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_drop(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"DROP TABLE %s", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_CREATE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_CREATE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
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

  MYSQL* mysql;  
  my_bool flag = TRUE;
  char* table="test";
  ulonglong origin_audit_ops = opt_audit_ops;
  uint origin_audit_class = opt_audit_class;
  static int success = 0;
  static int failed = 0;

  opt_audit_ops = 0;

  mysql_init(mysql);  
  if(!open_connection( mysql, host,user,password, database, port, sock,0))
  {
    printf("Error: Connection failed when testing the dml operation for audit\n");
    return FALSE;
  }

  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_DDL;

  flag = check_create(2,mysql,table);
  printf("Audit the create operation into file\n");
  if(flag)
  {
    success++;
    printf("Create: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Create: FAILED!\n");
  }

  flag = check_alter(2,mysql,table);
  printf("Audit the alter operation into file\n");
  if(flag)
  {
    success++;
    printf("Alter: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Alter: FAILED!\n");
  }  

  flag = check_drop(2,mysql,"test");
  printf("Audit the drop operation file\n");
  if(flag)
  {
    success++;
    printf("Drop: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Drop: FAILED!\n");
  } 

  opt_audit_class = 4;
  flag = check_create(4,mysql,"test");
  printf("Audit the create operation into table\n");
  if(flag)
  {
    success++;
    printf("Create: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Create: FAILED!\n");
  }

  flag = check_alter(4,mysql,"test");
  printf("Audit the alter operation into table\n");
  if(flag)
  {
    success++;
    printf("Alter: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Alter: FAILED!\n");
  } 

  flag = check_drop(4,mysql,"test");
  printf("Audit the drop operation table\n");
  if(flag)
  {
    success++;
    printf("Drop: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Drop: FAILED!\n");
  }  

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_DDL;

  flag = check_create(2,mysql,table);
  printf("Don't audit the create operation into file\n");
  if(!flag)
  {
    success++;
    printf("Create: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Create: FAILED!\n");
  }

  flag = check_alter(2,mysql,table);
  printf("Don't audit the alter operation into file\n");
  if(!flag)
  {
    success++;
    printf("Alter: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Alter: FAILED!\n");
  }  

  flag = check_drop(2,mysql,"test");
  printf("Don't audit the drop operation file\n");
  if(!flag)
  {
    success++;
    printf("Drop: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Drop: FAILED!\n");
  } 

  opt_audit_class = 4;
  flag = check_create(4,mysql,"test");
  printf("Don't audit the create operation into table\n");
  if(!flag)
  {
    success++;
    printf("Create: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Create: FAILED!\n");
  }

  flag = check_alter(4,mysql,"test");
  printf("Don't audit the alter operation into table\n");
  if(!flag)
  {
    success++;
    printf("Alter: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Alter: FAILED!\n");
  } 

  flag = check_drop(4,mysql,"test");
  printf("Don't audit the drop operation table\n");
  if(!flag)
  {
    success++;
    printf("Drop: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Drop: FAILED!\n");
  }  

  opt_audit_ops = origin_audit_ops;
  opt_audit_class = origin_audit_class;

  close_connection(mysql);

  printf("=============================\n");
  printf("total: %d, success: %d, failed: %d\n",success+failed,success,failed);
  return 0;   
}




