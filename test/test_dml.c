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

my_bool check_insert(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"INSERT INTO %s (ID, NAME) values(1,'abc')", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_INSERT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_INSERT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_update(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"UPDATE %s SET NAME='aaa' WHERE ID=1", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_UPDATE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_UPDATE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_replace(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"REPLACE INTO %s (ID,NAME) VALUES(1,'aaa')", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_REPLACE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_REPLACE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_select(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"SELECT ID,NAME FROM %s", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_SELECT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_SELECT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_delete(uint audit_class,MYSQL* mysql,char* table)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !table)
    return FALSE;
  my_snprintf(sql,FN_LEN,"DELETE FROM %s", table);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_DELETE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_DELETE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_set(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"SET NAMES utf8",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_SET_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_SET_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
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
  char sql[FN_LEN] = {0};
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
  my_snprintf(sql,FN_LEN,"CREATE TABLE IF NOT EXISTS %s (ID int, NAME varchar(20))", table);
  if(!execute_no_query(mysql,sql))
  {
    printf("Error: Create the table for test failed.\n");
    goto err;
  }

  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_DML;

  flag = check_insert(2,mysql,table);
  printf("Audit the insert operation into file\n");
  if(flag)
  {
    success++;
    printf("Insert: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Insert: FAILED!\n");
  }

  flag = check_update(2,mysql,table);
  printf("Audit the update operation into file\n");
  if(flag)
  {
    success++;
    printf("Update: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Update: FAILED!\n");
  }  

  flag = check_replace(2,mysql,table);
  printf("Audit the replace operation into file\n");
  if(flag)
  {
    success++;
    printf("Replace: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Replace: FAILED!\n");
  }  
  
  flag = check_select(2,mysql,table);
  printf("Audit the select operation file\n");
  if(flag)
  {
    success++;
    printf("Select: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Select: FAILED!\n");
  } 

  flag = check_delete(2,mysql,table);
  printf("Audit the delete operation file\n");
  if(flag)
  {
    success++;
    printf("Delete: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Delete: FAILED!\n");
  } 
  
  flag = check_set(2,mysql);
  printf("Audit the set operation file\n");
  if(flag)
  {
    success++;
    printf("Set: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Set: FAILED!\n");
  } 

  opt_audit_class = 4;
  flag = check_insert(4,mysql,table);
  printf("Audit the insert operation into table\n");
  if(flag)
  {
    success++;
    printf("Insert: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Insert: FAILED!\n");
  }

  flag = check_update(4,mysql,table);
  printf("Audit the update operation into table\n");
  if(flag)
  {
    success++;
    printf("Update: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Update: FAILED!\n");
  } 

  flag = check_replace(4,mysql,table);
  printf("Audit the replace operation into table\n");
  if(flag)
  {
    success++;
    printf("Replace: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Replace: FAILED!\n");
  }  
  
  flag = check_select(4,mysql,table);
  printf("Audit the select operation table\n");
  if(flag)
  {
    success++;
    printf("Select: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Select: FAILED!\n");
  }  

  flag = check_delete(4,mysql,table);
  printf("Audit the delete operation table\n");
  if(flag)
  {
    success++;
    printf("Delete: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Delete: FAILED!\n");
  } 

  flag = check_set(4,mysql);
  printf("Audit the set operation table\n");
  if(flag)
  {
    success++;
    printf("Set: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Set: FAILED!\n");
  } 
  
  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_DML;

  flag = check_insert(2,mysql,table);
  printf("Don't audit the insert operation into file\n");
  if(!flag)
  {
    success++;
    printf("Insert: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Insert: FAILED!\n");
  }

  flag = check_update(2,mysql,table);
  printf("Don't audit the update operation into file\n");
  if(!flag)
  {
    success++;
    printf("Update: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Update: FAILED!\n");
  }  
  
  flag = check_replace(2,mysql,table);
  printf("Don't audit the replace operation into file\n");
  if(!flag)
  {
    success++;
    printf("Replace: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Replace: FAILED!\n");
  }  

  flag = check_select(2,mysql,table);
  printf("Don't audit the select operation file\n");
  if(!flag)
  {
    success++;
    printf("Select: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Select: FAILED!\n");
  } 

  flag = check_delete(2,mysql,table);
  printf("Don't audit the delete operation file\n");
  if(!flag)
  {
    success++;
    printf("Delete: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Delete: FAILED!\n");
  } 
  
  flag = check_set(2,mysql);
  printf("Don't audit the set operation file\n");
  if(!flag)
  {
    success++;
    printf("Set: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Set: FAILED!\n");
  } 

  opt_audit_class = 4;
  flag = check_insert(4,mysql,table);
  printf("Don't audit the insert operation into table\n");
  if(!flag)
  {
    success++;
    printf("Insert: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Insert: FAILED!\n");
  }

  flag = check_update(4,mysql,table);
  printf("Don't audit the update operation into table\n");
  if(!flag)
  {
    success++;
    printf("Update: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Update: FAILED!\n");
  } 

  flag = check_replace(4,mysql,table);
  printf("Don't audit the replace operation into table\n");
  if(!flag)
  {
    success++;
    printf("Replace: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Replace: FAILED!\n");
  } 
  
  flag = check_select(4,mysql,table);
  printf("Don't audit the select operation table\n");
  if(!flag)
  {
    success++;
    printf("Select: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Select: FAILED!\n");
  }  

  flag = check_delete(4,mysql,table);
  printf("Don't audit the delete operation table\n");
  if(!flag)
  {
    success++;
    printf("Delete: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Delete: FAILED!\n");
  } 

  flag = check_set(4,mysql);
  printf("Don't audit the set operation table\n");
  if(!flag)
  {
    success++;
    printf("Set: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Set: FAILED!\n");
  } 
  
  opt_audit_class = origin_audit_class;
  opt_audit_ops =origin_audit_ops;

  my_snprintf(sql,FN_LEN,"DROP TABLE %s ", table);
  if(!execute_no_query(mysql,sql))
  {
    printf("Error: Drop the table for test failed.\n");
    goto err;
  }

err:
  close_connection(mysql);

  printf("=============================\n");
  printf("total: %d, success: %d, failed: %d\n",success+failed,success,failed);
  return 0;   
}




