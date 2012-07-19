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

/*
my_bool check_sleep(uint audit_class,MYSQL* mysql)
{

}

my_bool check_init_db(uint audit_class,MYSQL* mysql)
{

}*/


my_bool check_field_list(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"SHOW COLUMNS FROM MYSQL.USER",FN_LEN);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_FIELD_LIST_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_FIELD_LIST_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_refresh(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_refresh(mysql,2);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_REFRESH_NAME.str,mysql->host,mysql->user);
  }
  else{
    opt_audit_class = 4;
    mysql_refresh(mysql,2);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_REFRESH_NAME.str,"host",mysql->host,"user",mysql->user);
  }
}

my_bool check_shutdown(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_shutdown(mysql,0);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_SHUTDOWN_NAME.str,mysql->host,mysql->user);
  }
  else{
    opt_audit_class = 4;
    mysql_shutdown(mysql,0);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_SHUTDOWN_NAME.str,"host",mysql->host,"user",mysql->user);
  }
}

/*
my_bool check_statistics(uint audit_class,MYSQL* mysql)
{

}*/


my_bool check_processlist(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_list_processes(mysql);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_PROCESSLIST_NAME.str,mysql->host,mysql->user);
  }
  else{
    opt_audit_class = 4;
    mysql_list_processes(mysql);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_PROCESSLIST_NAME.str,"host",mysql->host,"user",mysql->user);
  }
}

my_bool check_kill(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  my_snprintf(sql,FN_LEN,"KILL %s", mysql->thread_id);
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_KILL_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    if(!execute_no_query(mysql,sql))
      return FALSE;
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_KILL_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

my_bool check_debug(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
#ifdef WIN32
  const char* str = "d:t:O,C:/client.trace";
#else
  const char* str = "d:t:O,/tmp/client.trace";
#endif

  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_debug(str);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_DEBUG_NAME.str,mysql->host,mysql->user,str);
  }
  else{
    opt_audit_class = 4;
    mysql_debug(str);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_DEBUG_NAME.str,"host",mysql->host,"user",mysql->user,"query",str);
  }
}

my_bool check_ping(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_ping(mysql);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_PING_NAME.str,mysql->host,mysql->user);
  }
  else{
    opt_audit_class = 4;
    mysql_ping(mysql);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_PING_NAME.str,"host",mysql->host,"user",mysql->user);
  }
}

/*
my_bool check_time(uint audit_class,MYSQL* mysql)
{

}

my_bool check_delay_insert(uint audit_class,MYSQL* mysql)
{

}

my_bool check_binlog_dump(uint audit_class,MYSQL* mysql)
{

}

my_bool check_table_dump(uint audit_class,MYSQL* mysql)
{

}

my_bool check_connect_out(uint audit_class,MYSQL* mysql)
{

}

my_bool check_register_slave(uint audit_class,MYSQL* mysql)
{

}

my_bool check_prepare(uint audit_class,MYSQL* mysql)
{

}

my_bool check_execute(uint audit_class,MYSQL* mysql)
{

}

my_bool check_long_data(uint audit_class,MYSQL* mysql)
{

}

my_bool check_close_stmt(uint audit_class,MYSQL* mysql)
{

}

my_bool check_reset_stmt(uint audit_class,MYSQL* mysql)
{

}*/


my_bool check_set_option(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_set_server_option(mysql,0);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_SET_OPTION_NAME.str);
  }
  else{
    opt_audit_class = 4;
    mysql_set_server_option(mysql,0);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_SET_OPTION_NAME.str,"host",mysql->host,"user",mysql->user);
  }
}

my_bool check_fetch(uint audit_class,MYSQL* mysql)
{
  MYSQL_RES* res;
  MYSQL_ROW row ;  
  char* pfile,*pdate;
  char sql[FN_LEN] = {0};
  if(!mysql)
    return FALSE;
  strmake(sql,"SELECT host,user,password FROM MYSQL.USER",FN_LEN);

  if(!(res = execute_query(mysql,sql)))
    return FALSE;

  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    row = mysql_fetch_row(res);
    if(res)
      mysql_free_result(res);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_FETCH_NAME.str,mysql->host,mysql->user,sql);
  }
  else{
    opt_audit_class = 4;
    row = mysql_fetch_row(res);
    if(res)
      mysql_free_result(res);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_FETCH_NAME.str,"host",mysql->host,"user",mysql->user,"query",sql);
  }
}

/*
my_bool check_daemon(uint audit_class,MYSQL* mysql)
{

}*/


my_bool check_error(uint audit_class,MYSQL* mysql)
{
  char* pfile,*pdate;
  if(!mysql)
    return FALSE;
  pdate = get_current_datetime(audit_datetime);

  if(audit_class == 2)
  {
    opt_audit_class = 2;
    mysql_error(mysql);
    pfile = get_audit_file_name(audit_name,FILE_NAME_LEN);
    return check_file_result(pfile,pdate,AUDIT_SET_OPTION_NAME.str);
  }
  else{
    opt_audit_class = 4;
    mysql_error(mysql);
    pfile = get_audit_table_name(audit_name,FILE_NAME_LEN);
    return check_table_result(pfile,pdate,"command",AUDIT_SET_OPTION_NAME.str,"host",mysql->host,"user",mysql->user);
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

  mysql_init(mysql);  

  opt_audit_ops = 0;

  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_SET_OPTION;
  flag = check_set_option(2,mysql);
  printf("Audit the set option operation into file\n");
  if(flag)
  {
    success++;
    printf("Set option: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Set option: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_set_option(4,mysql);
  printf("Audit the set option operation into table\n");
  if(flag)
  {
    success++;
    printf("Set option: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Set option: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_SET_OPTION;
  flag = check_set_option(2,mysql);
  printf("Don't audit the set option operation into file\n");
  if(!flag)
  {
    success++;
    printf("Set option: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Set option: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_set_option(4,mysql);
  printf("Don't audit the set option operation into table\n");
  if(!flag)
  {
    success++;
    printf("Set option: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Set option: FAILED!\n");
  }

  if(!open_connection( mysql, host,user,password, database, port, sock,0))
  {
    printf("Error: Connection failed when testing the dml operation for audit\n");
    return FALSE;
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_FIELD_LIST;
  flag = check_field_list(2,mysql);
  printf("Audit the field list operation into file\n");
  if(flag)
  {
    success++;
    printf("Field list: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Field list: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_field_list(4,mysql);
  printf("Audit the field list operation into table\n");
  if(flag)
  {
    success++;
    printf("Field list: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Field list: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_FIELD_LIST;
  flag = check_field_list(2,mysql);
  printf("Don't audit the field list operation into file\n");
  if(!flag)
  {
    success++;
    printf("Field list: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Field list: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_field_list(4,mysql);
  printf("Don't audit the field list operation into table\n");
  if(!flag)
  {
    success++;
    printf("Field list: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Field list: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_REFRESH;
  flag = check_refresh(2,mysql);
  printf("Audit the refresh operation into file\n");
  if(flag)
  {
    success++;
    printf("Refresh: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Refresh: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_refresh(4,mysql);
  printf("Audit the refresh operation into table\n");
  if(flag)
  {
    success++;
    printf("Refresh: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Refresh: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_REFRESH;
  flag = check_refresh(2,mysql);
  printf("Don't audit the refresh operation into file\n");
  if(!flag)
  {
    success++;
    printf("Refresh: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Refresh: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_refresh(4,mysql);
  printf("Don't audit the refresh operation into table\n");
  if(!flag)
  {
    success++;
    printf("Refresh: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Refresh: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |= AUDIT_PROCESSLIST;
  flag = check_processlist(2,mysql);
  printf("Audit the processlist operation into file\n");
  if(flag)
  {
    success++;
    printf("Processlist: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Processlist: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_processlist(4,mysql);
  printf("Audit the processlist operation into table\n");
  if(flag)
  {
    success++;
    printf("Processlist: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Processlist: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_PROCESSLIST;
  flag = check_processlist(2,mysql);
  printf("Don't audit the processlist operation into file\n");
  if(!flag)
  {
    success++;
    printf("Processlist: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Processlist: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_processlist(4,mysql);
  printf("Don't audit the processlist operation into table\n");
  if(!flag)
  {
    success++;
    printf("Processlist: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Processlist: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_DEBUG;
  flag = check_debug(2,mysql);
  printf("Audit the debug operation into file\n");
  if(flag)
  {
    success++;
    printf("Debug: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Debug: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_debug(4,mysql);
  printf("Audit the debug operation into table\n");
  if(flag)
  {
    success++;
    printf("Debug: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Debug: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_DEBUG;
  flag = check_debug(2,mysql);
  printf("Don't audit the debug operation into file\n");
  if(!flag)
  {
    success++;
    printf("Debug: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Debug: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_debug(4,mysql);
  printf("Don't audit the debug operation into table\n");
  if(!flag)
  {
    success++;
    printf("Debug: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Debug: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_PING;
  flag = check_ping(2,mysql);
  printf("Audit the ping operation into file\n");
  if(flag)
  {
    success++;
    printf("Ping: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Ping: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_ping(4,mysql);
  printf("Audit the ping operation into table\n");
  if(flag)
  {
    success++;
    printf("Ping: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Ping: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_PING;
  flag = check_ping(2,mysql);
  printf("Don't audit the ping operation into file\n");
  if(!flag)
  {
    success++;
    printf("Ping: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Ping: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_ping(4,mysql);
  printf("Don't audit the ping operation into table\n");
  if(!flag)
  {
    success++;
    printf("Ping: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Ping: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_FETCH;
  flag = check_fetch(2,mysql);
  printf("Audit the fetch operation into file\n");
  if(flag)
  {
    success++;
    printf("Fetch: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Fetch: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_fetch(4,mysql);
  printf("Audit the fetch operation into table\n");
  if(flag)
  {
    success++;
    printf("Fetch: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Fetch: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_FETCH;
  flag = check_fetch(2,mysql);
  printf("Don't audit the fetch operation into file\n");
  if(!flag)
  {
    success++;
    printf("Fetch: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Fetch: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_fetch(4,mysql);
  printf("Don't audit the fetch operation into table\n");
  if(!flag)
  {
    success++;
    printf("Fetch: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Fetch: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_ERROR;
  flag = check_error(2,mysql);
  printf("Audit the error operation into file\n");
  if(flag)
  {
    success++;
    printf("Error: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Error: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_error(4,mysql);
  printf("Audit the error operation into table\n");
  if(flag)
  {
    success++;
    printf("Error: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Error: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_ERROR;
  flag = check_error(2,mysql);
  printf("Don't audit the error operation into file\n");
  if(!flag)
  {
    success++;
    printf("Error: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Error: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_error(4,mysql);
  printf("Don't audit the error operation into table\n");
  if(!flag)
  {
    success++;
    printf("Error: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Error: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_KILL;
  flag = check_kill(2,mysql);
  printf("Audit the kill operation into file\n");
  if(flag)
  {
    success++;
    printf("Kill: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Kill: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_kill(4,mysql);
  printf("Audit the kill operation into table\n");
  if(flag)
  {
    success++;
    printf("Kill: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Kill: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_KILL;
  flag = check_kill(2,mysql);
  printf("Don't audit the kill operation into file\n");
  if(!flag)
  {
    success++;
    printf("Kill: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Kill: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_kill(4,mysql);
  printf("Don't audit the kill operation into table\n");
  if(!flag)
  {
    success++;
    printf("Kill: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Kill: FAILED!\n");
  }

  opt_audit_ops = 0;
  opt_audit_class = 2;
  opt_audit_ops |=AUDIT_SHUTDOWN;
  flag = check_shutdown(2,mysql);
  printf("Audit the shutdown operation into file\n");
  if(flag)
  {
    success++;
    printf("Shutdown: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Shutdown: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_shutdown(4,mysql);
  printf("Audit the shutdown operation into table\n");
  if(flag)
  {
    success++;
    printf("Shutdown: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Shutdown: FAILED!\n");
  }

  opt_audit_class = 2;
  opt_audit_ops &=~AUDIT_SHUTDOWN;
  flag = check_shutdown(2,mysql);
  printf("Don't audit the shutdown operation into file\n");
  if(!flag)
  {
    success++;
    printf("Shutdown: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Shutdown: FAILED!\n");
  }

  opt_audit_class = 4;
  flag = check_shutdown(4,mysql);
  printf("Don't audit the shutdown operation into table\n");
  if(!flag)
  {
    success++;
    printf("Shutdown: SUCCESS!\n");
  }
  else{
    failed++;
    printf("Shutdown: FAILED!\n");
  }

  opt_audit_class = origin_audit_class;
  opt_audit_ops = origin_audit_ops;

  close_connection(mysql);

  printf("=============================\n");
  printf("total: %d, success: %d, failed: %d\n",success+failed,success,failed);
  return 0;   
}




