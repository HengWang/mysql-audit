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

my_bool check_grant(uint audit_class,MYSQL* mysql,char* user, char* host)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !user || !host)
    return FALSE;
  my_snprintf(sql,FN_LEN,"GRANT ALL ON *.* '%s'@'%s' IDENTIFIED BY 'audit'", user,host);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_GRANT_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    my_snprintf(sql,FN_LEN,"GRANT ALL ON *.* '%s'@'%s' IDENTIFIED BY '#####'", user,host);
    return check_table_result(pfile,pdate,"command",AUDIT_GRANT_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_revoke(uint audit_class,MYSQL* mysql,char* user,char* host)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql || !user || !host)
    return FALSE;
  my_snprintf(sql,FN_LEN,"REVOKE ALL ON *.* FROM '%s'.'%s'", user,host);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_REVOKE_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_REVOKE_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
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
  opt_audit_ops |= AUDIT_DCL;

  flag = check_grant(2,mysql,"test",host);
  printf("Audit the grant operation into file\n");
  if(flag)
  {
    success++;
    printf("Grant: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Grant: FAILED!\n");
  }

  flag = check_revoke(2,mysql,"test",host);
  printf("Audit the revoke operation into file\n");
  if(flag)
  {
    success++;
    printf("Revoke: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Revoke: FAILED!\n");
  }  

  opt_audit_class = 4;
  flag = check_grant(4,mysql,"test",host);
  printf("Audit the grant operation into table\n");
  if(flag)
  {
    success++;
    printf("Grant: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Grant: FAILED!\n");
  }

  flag = check_revoke(4,mysql,"test",host);
  printf("Audit the revoke operation into table\n");
  if(flag)
  {
    success++;
    printf("Revoke: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Revoke: FAILED!\n");
  } 

  opt_audit_class = 2;
  opt_audit_ops &= ~AUDIT_DCL;

  flag = check_grant(2,mysql,"test",host);
  printf("Don't audit the grant operation into file\n");
  if(!flag)
  {
    success++;
    printf("Grant: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Grant: FAILED!\n");
  }

  flag = check_revoke(2,mysql,"test",host);
  printf("Don't audit the revoke operation into file\n");
  if(!flag)
  {
    success++;
    printf("Revoke: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Revoke: FAILED!\n");
  }  

  opt_audit_class = 4;
  flag = check_grant(4,mysql,"test",host);
  printf("Don't audit the grant operation into table\n");
  if(!flag)
  {
    success++;
    printf("Grant: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Grant: FAILED!\n");
  }

  flag = check_revoke(4,mysql,"test",host);
  printf("Don't audit the revoke operation into table\n");
  if(!flag)
  {
    success++;
    printf("Revoke: SUCCESS!\n");
  } 
  else{
    failed++;
    printf("Revoke: FAILED!\n");
  } 

  opt_audit_class = origin_audit_class;
  opt_audit_ops = origin_audit_ops;

  close_connection(mysql);

  printf("=============================\n");
  printf("total: %d, success: %d, failed: %d\n",success+failed,success,failed);
  return 0;   
}




