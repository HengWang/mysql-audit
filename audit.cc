/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <my_sys.h>
#include <sql/sql_class.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <audit.h>
#include <audit_file.h>
#include <audit_table.h>
#include <common.h>
#include "audit_config.h"


#if !defined(__attribute__) && (defined(__cplusplus) || !defined(__GNUC__)  || __GNUC__ == 2 && __GNUC_MINOR__ < 8)
#define __attribute__(A)
#endif

/* The group name of audit in configure file. */
#define AUDIT_GROUP                   "AUDIT"

/* The status name of bool options. */
#define ON_STATUS                        "ON"
#define OFF_STATUS                      "OFF"

/* The log class name. */
#define LOG_FILE_STR                  "FILE"
#define LOG_TABLE_STR              "TABLE"

/* The delimiter keyword. */
#define DELIM_KEY                        ","

/* The unit of type name. */
#define GB_TYPE                            "GB"
#define MB_TYPE                            "MB"
#define KB_TYPE                             "KB"
#define G_TYPE                               "G"
#define M_TYPE                               "M"
#define K_TYPE                                "K"

/* The size of type. */
#define GB_SIZE                               (1024*1024*1024)
#define MB_SIZE                               (1024*1024)
#define KB_SIZE                                (1024)

/* The command number. */
#define CMD_NUM                            60

/* The password column. */
#define PWD_COLUMN 3

/**
* The audit variables 
*/
typedef enum enum_audit_variables{
  VAR_DIR,VAR_FILE,VAR_FILE_SIZE,VAR_USERS,VAR_DBS,
  VAR_TABLES,VAR_IGNORE_USERS,VAR_IGNORE_DBS,VAR_IGNORE_TABLES,VAR_CLASS,VAR_OPS,VAR_ALL,VAR_FULL,
  VAR_CMD,VAR_CREATE,VAR_DROP,VAR_ALTER,VAR_DDL,
  VAR_INSERT,VAR_DELETE,VAR_UPDATE,VAR_REPLACE,VAR_MODIFY,VAR_SELECT,
  VAR_DML,VAR_GRANT,VAR_REVOKE,VAR_DCL,VAR_SET,VAR_CONNECT,
  VAR_QUIT,VAR_CHANGE_USER,VAR_CONNECTION,VAR_SERVER,VAR_SLEEP,
  VAR_INIT_DB,VAR_FIELD_LIST,VAR_REFRESH,VAR_SHUTDOWN,VAR_STATISTICS,
  VAR_PROCESSLIST,VAR_KILL,VAR_DEBUG,VAR_PING,VAR_TIME,
  VAR_DELAY_INSERT,VAR_BINLOG_DUMP,VAR_TABLE_DUMP,VAR_CONNECT_OUT,VAR_REGISTER_SLAVE,
  VAR_PREPARE,VAR_EXECUTE,VAR_LONG_DATA,VAR_CLOSE_STMT,VAR_RESET_STMT,
  VAR_SET_OPTION,VAR_FETCH,VAR_DAEMON,VAR_ERROR} EAV;

  /**
  * The default options command.
  */
  const char * default_options[CMD_NUM] = {"audit_dir","audit_file","audit_file_size","audit_users","audit_dbs",
    "audit_tables","ignore_users","ignore_dbs","ignore_tables","audit_class","audit_ops","audit_all","audit_full",
    "audit_cmd","audit_create","audit_drop","audit_alter","audit_ddl",
    "audit_insert","audit_delete","audit_update","audit_replace","audit_modify","audit_select",
    "audit_dml","audit_grant","audit_revoke","audit_dcl","audit_set","audit_connect",
    "audit_quit","audit_change_user","audit_connection","audit_server","audit_sleep",
    "audit_init_db","audit_field_list","audit_refresh","audit_shutdown","audit_statistics",
    "audit_processlist","audit_kill","audit_debug","audit_ping","audit_time",
    "audit_delay_insert","audit_binlog_dump","audit_table_dump","audit_connect_out","audit_register_slave",
    "audit_prepare","audit_execute","audit_long_data","audit_close_stmt","audit_reset_stmt",
    "audit_set_option","audit_fetch","audit_daemon","audit_error",0};

  /**
  * Declaration of MYSQL schema name and define the table USER name
  */
  LEX_STRING MYSQL_SCHEMA_NAME= {C_STRING_WITH_LEN("mysql")};
  const LEX_STRING USER_NAME = {C_STRING_WITH_LEN("user")};
  const LEX_STRING MYSQL_USER_NAME = {C_STRING_WITH_LEN("mysql.user")};
  const LEX_STRING PASSWORD_NAME = {C_STRING_WITH_LEN("password")};
  /**
  * The audit command name definition
  */
  LEX_STRING AUDIT_CONNECT_NAME = { C_STRING_WITH_LEN("Connect") };    
  LEX_STRING AUDIT_QUIT_NAME = { C_STRING_WITH_LEN("Quit") };   
  LEX_STRING AUDIT_CHANGE_USER_NAME = { C_STRING_WITH_LEN("Change user") };    
  LEX_STRING AUDIT_CREATE_NAME = { C_STRING_WITH_LEN("Create") };    
  LEX_STRING AUDIT_ALTER_NAME= { C_STRING_WITH_LEN("Alter") };  
  LEX_STRING AUDIT_DROP_NAME = { C_STRING_WITH_LEN("Drop") };  
  LEX_STRING AUDIT_INSERT_NAME   =    { C_STRING_WITH_LEN( "Insert") };  
  LEX_STRING AUDIT_UPDATE_NAME =    { C_STRING_WITH_LEN("Update") }; 
  LEX_STRING AUDIT_REPLACE_NAME =    { C_STRING_WITH_LEN("Replace") };   
  LEX_STRING AUDIT_DELETE_NAME   =    { C_STRING_WITH_LEN( "Delete") };  
  LEX_STRING AUDIT_SELECT_NAME   =     { C_STRING_WITH_LEN( "Select") };  
  LEX_STRING AUDIT_GRANT_NAME    =      { C_STRING_WITH_LEN("Grant") };  
  LEX_STRING AUDIT_REVOKE_NAME =      { C_STRING_WITH_LEN( "Revoke") };  
  LEX_STRING AUDIT_SET_NAME =      { C_STRING_WITH_LEN( "Set") };
  LEX_STRING AUDIT_SLEEP_NAME = { C_STRING_WITH_LEN("Sleep") };
  LEX_STRING AUDIT_INIT_DB_NAME =     { C_STRING_WITH_LEN("Init DB") };
  LEX_STRING AUDIT_FIELD_LIST_NAME =    { C_STRING_WITH_LEN("Field List") };
  LEX_STRING AUDIT_REFRESH_NAME =     { C_STRING_WITH_LEN("Refresh") };
  LEX_STRING AUDIT_SHUTDOWN_NAME =  { C_STRING_WITH_LEN("Shutdown") };
  LEX_STRING AUDIT_STATISTICS_NAME =    { C_STRING_WITH_LEN("Statistics") };
  LEX_STRING AUDIT_PROCESSLIST_NAME =     { C_STRING_WITH_LEN("Processlist") };
  LEX_STRING AUDIT_KILL_NAME =    { C_STRING_WITH_LEN("Kill") };
  LEX_STRING AUDIT_DEBUG_NAME =     { C_STRING_WITH_LEN("Debug") };
  LEX_STRING AUDIT_PING_NAME =    { C_STRING_WITH_LEN("Ping") };
  LEX_STRING AUDIT_TIME_NAME =    { C_STRING_WITH_LEN("Time") };
  LEX_STRING AUDIT_DELAY_INSERT_NAME =  { C_STRING_WITH_LEN("Delayed insert") };
  LEX_STRING AUDIT_BINLOG_DUMP_NAME =     { C_STRING_WITH_LEN("Binlog Dump") };
  LEX_STRING AUDIT_TABLE_DUMP_NAME =  { C_STRING_WITH_LEN("Table Dump") };
  LEX_STRING AUDIT_CONNECT_OUT_NAME =   { C_STRING_WITH_LEN("Connect Out") };
  LEX_STRING AUDIT_REGISTER_SLAVE_NAME =  { C_STRING_WITH_LEN("Register Slave") };
  LEX_STRING AUDIT_PREPARE_NAME =   { C_STRING_WITH_LEN("Prepare") };
  LEX_STRING AUDIT_EXECUTE_NAME =   { C_STRING_WITH_LEN("Execute") };
  LEX_STRING AUDIT_LONG_DATA_NAME =   { C_STRING_WITH_LEN("Long Data") };
  LEX_STRING AUDIT_CLOSE_STMT_NAME =    { C_STRING_WITH_LEN("Close stmt") };
  LEX_STRING AUDIT_RESET_STMT_NAME =  { C_STRING_WITH_LEN("Reset stmt") };
  LEX_STRING AUDIT_SET_OPTION_NAME =  { C_STRING_WITH_LEN("Set option") };
  LEX_STRING AUDIT_FETCH_NAME =   { C_STRING_WITH_LEN("Fetch") };
  LEX_STRING AUDIT_DAEMON_NAME =  { C_STRING_WITH_LEN("Daemon") };
  LEX_STRING AUDIT_ERROR_NAME =   { C_STRING_WITH_LEN("Error") } ; 

  /**
  * The audit users dbs and tables storage structure declaration
  */
  DYNAMIC_ARRAY* audit_users;
  DYNAMIC_ARRAY* audit_dbs;
  DYNAMIC_ARRAY* audit_tables;
  /**
  * The audit ignore the users dbs and tables storage structure declaration
  */
  DYNAMIC_ARRAY* ignore_users;
  DYNAMIC_ARRAY* ignore_dbs;
  DYNAMIC_ARRAY* ignore_tables;

  /* The stat decriptor of configure file*/
  MY_STAT config_stat;

  //The number of audited commands.
  static volatile int commands;

  /* Global variables */
  ulonglong opt_audit_file_size = 0;
  ulonglong opt_audit_ops = 0;
  uint opt_audit_class = 0;
  char *opt_audit_users = 0;
  char *opt_audit_dbs = 0;
  char *opt_audit_tables = 0;
  char *opt_ignore_users = 0;
  char *opt_ignore_dbs = 0;
  char *opt_ignore_tables = 0;
  
  char *opt_audit_dir = 0;
  char *opt_audit_file = 0;
  char default_audit_dir[FN_REFLEN];
  char default_audit_filename[FN_REFLEN];

  /*The configure file path name*/
#if !defined(__WIN__)
  const char* config_file = "../lib/plugin/audit.cnf";
#else
  const char * config_file = "../lib/plugin/audit.ini";
#endif

  /*
  Prepare the general operations for current query.

  SYNOPSIS
  prepare_general_ops()
  my_event_gen    The mysql event general object   
  op_str                The general operation string type.

  DESCRIPTION
  Prepare the general operations for current query.
  */
  char* prepare_general_ops(struct mysql_event_general *my_event_gen, char* op_str )
  {
    DBUG_ENTER("prepare_general_ops");
    /*The insert operation*/
    if((opt_audit_ops & AUDIT_CREATE) && 
      !strncasecmp(my_event_gen->general_query,AUDIT_CREATE_NAME.str,AUDIT_CREATE_NAME.length))
    {
      strmake(op_str, AUDIT_CREATE_NAME.str, AUDIT_CREATE_NAME.length);
    }
    /*The drop operation*/
    else if((opt_audit_ops & AUDIT_DROP) && 
      !strncasecmp(my_event_gen->general_query,AUDIT_DROP_NAME.str,AUDIT_DROP_NAME.length))
    {
      strmake(op_str, AUDIT_DROP_NAME.str, AUDIT_DROP_NAME.length);
    }
    /*The alter operation*/
    else if((opt_audit_ops & AUDIT_ALTER) && 
      !strncasecmp(my_event_gen->general_query,AUDIT_ALTER_NAME.str,AUDIT_ALTER_NAME.length))
    {
      strmake(op_str, AUDIT_ALTER_NAME.str, AUDIT_ALTER_NAME.length);
    } 
    /*The insert operation*/
    else if((opt_audit_ops & AUDIT_INSERT) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_INSERT_NAME.str,AUDIT_INSERT_NAME.length))
    {
      strmake(op_str, AUDIT_INSERT_NAME.str, AUDIT_INSERT_NAME.length);
    } 
    /*The delete operation*/
    else if((opt_audit_ops & AUDIT_DELETE) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_DELETE_NAME.str,AUDIT_DELETE_NAME.length))
    {
      strmake(op_str, AUDIT_DELETE_NAME.str, AUDIT_DELETE_NAME.length);
    }
    /*The update operation*/
    else if((opt_audit_ops & AUDIT_UPDATE) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_UPDATE_NAME.str,AUDIT_UPDATE_NAME.length))
    {
      strmake(op_str, AUDIT_UPDATE_NAME.str,AUDIT_UPDATE_NAME.length);
    }
    /*The replace operation*/
    else if((opt_audit_ops & AUDIT_REPLACE) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_REPLACE_NAME.str,AUDIT_REPLACE_NAME.length))
    {
      strmake(op_str, AUDIT_REPLACE_NAME.str,AUDIT_REPLACE_NAME.length);
    }
    /*The select operation*/
    else if((opt_audit_ops & AUDIT_SELECT) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_SELECT_NAME.str,AUDIT_SELECT_NAME.length))
    {
      strmake(op_str, AUDIT_SELECT_NAME.str, AUDIT_SELECT_NAME.length);
    }
    /*The grant operation*/
    else if((opt_audit_ops & AUDIT_GRANT) &&      
      !strncasecmp(my_event_gen->general_query,AUDIT_GRANT_NAME.str,AUDIT_GRANT_NAME.length))
    {
      strmake(op_str, AUDIT_GRANT_NAME.str, AUDIT_GRANT_NAME.length);
    }
    /*The revoke operation*/
    else if((opt_audit_ops & AUDIT_REVOKE) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_REVOKE_NAME.str,AUDIT_REVOKE_NAME.length))
    {
      strmake(op_str, AUDIT_REVOKE_NAME.str, AUDIT_REVOKE_NAME.length);
    }
    /*The set operation*/
    else if((opt_audit_ops & AUDIT_SET) &&     
      !strncasecmp(my_event_gen->general_query,AUDIT_SET_NAME.str,AUDIT_SET_NAME.length))
    {
      strmake(op_str, AUDIT_SET_NAME.str, AUDIT_SET_NAME.length);
    }
    /* The sleep operation*/
    else if((opt_audit_ops & AUDIT_SLEEP)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_SLEEP_NAME.str,AUDIT_SLEEP_NAME.length))
    {
      strmake(op_str, AUDIT_SLEEP_NAME.str,AUDIT_SLEEP_NAME.length);
    }
    /* The initial db operation*/
    else if((opt_audit_ops & AUDIT_INIT_DB)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_INIT_DB_NAME.str,AUDIT_INIT_DB_NAME.length))
    {
      strmake(op_str, AUDIT_INIT_DB_NAME.str,AUDIT_INIT_DB_NAME.length);
    }
    /* The filed list operation*/
    else if((opt_audit_ops & AUDIT_FIELD_LIST)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_FIELD_LIST_NAME.str,AUDIT_FIELD_LIST_NAME.length))
    {
      strmake(op_str, AUDIT_FIELD_LIST_NAME.str,AUDIT_FIELD_LIST_NAME.length);
    }
    /* The refresh operation*/
    else if((opt_audit_ops & AUDIT_REFRESH)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_REFRESH_NAME.str,AUDIT_REFRESH_NAME.length))
    {
      strmake(op_str, AUDIT_REFRESH_NAME.str,AUDIT_REFRESH_NAME.length);
    }
    /* The shutdown operation*/
    else if((opt_audit_ops & AUDIT_SHUTDOWN)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_SHUTDOWN_NAME.str,AUDIT_SHUTDOWN_NAME.length))
    {
      strmake(op_str, AUDIT_SHUTDOWN_NAME.str,AUDIT_SHUTDOWN_NAME.length);
    }
    /* The statistics operation*/
    else if((opt_audit_ops & AUDIT_STATISTICS)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_STATISTICS_NAME.str,AUDIT_STATISTICS_NAME.length))
    {
      strmake(op_str, AUDIT_STATISTICS_NAME.str,AUDIT_STATISTICS_NAME.length);
    }
    /* The processlist operation*/
    else if((opt_audit_ops & AUDIT_PROCESSLIST)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_PROCESSLIST_NAME.str,AUDIT_PROCESSLIST_NAME.length))
    {
      strmake(op_str, AUDIT_PROCESSLIST_NAME.str,AUDIT_PROCESSLIST_NAME.length);
    }
    /* The kill operation*/
    else if((opt_audit_ops & AUDIT_KILL)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_KILL_NAME.str,AUDIT_KILL_NAME.length))
    {
      strmake(op_str, AUDIT_KILL_NAME.str,AUDIT_KILL_NAME.length);
    }
    /* The debug operation*/
    else if((opt_audit_ops & AUDIT_DEBUG)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_DEBUG_NAME.str,AUDIT_DEBUG_NAME.length))
    {
      strmake(op_str, AUDIT_DEBUG_NAME.str,AUDIT_DEBUG_NAME.length);
    }
    /* The ping operation*/
    else if((opt_audit_ops & AUDIT_PING)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_PING_NAME.str,AUDIT_PING_NAME.length))
    {
      strmake(op_str, AUDIT_PING_NAME.str,AUDIT_PING_NAME.length);
    }
    /* The time operation*/
    else if((opt_audit_ops & AUDIT_TIME)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_TIME_NAME.str,AUDIT_TIME_NAME.length))
    {
      strmake(op_str, AUDIT_TIME_NAME.str,AUDIT_TIME_NAME.length);
    }
    /* The delay insert  operation*/
    else if((opt_audit_ops & AUDIT_DELAY_INSERT)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_DELAY_INSERT_NAME.str,AUDIT_DELAY_INSERT_NAME.length))
    {
      strmake(op_str, AUDIT_DELAY_INSERT_NAME.str,AUDIT_DELAY_INSERT_NAME.length);
    }
    /* The binlog dump operation*/
    else if((opt_audit_ops & AUDIT_BINLOG_DUMP)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_BINLOG_DUMP_NAME.str,AUDIT_BINLOG_DUMP_NAME.length))
    {
      strmake(op_str,AUDIT_BINLOG_DUMP_NAME.str,AUDIT_BINLOG_DUMP_NAME.length);
    }
    /* The table dump operation*/
    else if((opt_audit_ops & AUDIT_TABLE_DUMP)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_TABLE_DUMP_NAME.str,AUDIT_TABLE_DUMP_NAME.length))
    {
      strmake(op_str, AUDIT_TABLE_DUMP_NAME.str,AUDIT_TABLE_DUMP_NAME.length);
    }
    /* The connection out operation*/
    else if((opt_audit_ops & AUDIT_CONNECT_OUT)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_CONNECT_OUT_NAME.str,AUDIT_CONNECT_OUT_NAME.length))
    {
      strmake(op_str, AUDIT_CONNECT_OUT_NAME.str,AUDIT_CONNECT_OUT_NAME.length);
    }
    /* The register slave operation*/
    else if((opt_audit_ops & AUDIT_REGISTER_SLAVE)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_REGISTER_SLAVE_NAME.str,AUDIT_REGISTER_SLAVE_NAME.length))
    {
      strmake(op_str, AUDIT_REGISTER_SLAVE_NAME.str,AUDIT_REGISTER_SLAVE_NAME.length);
    }
    /* The prepare operation*/
    else if((opt_audit_ops & AUDIT_PREPARE)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_PREPARE_NAME.str,AUDIT_PREPARE_NAME.length))
    {
      strmake(op_str,AUDIT_PREPARE_NAME.str,AUDIT_PREPARE_NAME.length);
    }
    /* The execute operation*/
    else if((opt_audit_ops &AUDIT_EXECUTE)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_EXECUTE_NAME.str,AUDIT_EXECUTE_NAME.length))
    {
      strmake(op_str, AUDIT_EXECUTE_NAME.str,AUDIT_EXECUTE_NAME.length);
    }
    /* The long data operation*/
    else if((opt_audit_ops & AUDIT_LONG_DATA)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_LONG_DATA_NAME.str,AUDIT_LONG_DATA_NAME.length))
    {
      strmake(op_str, AUDIT_LONG_DATA_NAME.str,AUDIT_LONG_DATA_NAME.length);
    }
    /* The close statement operation*/
    else if((opt_audit_ops & AUDIT_CLOSE_STMT)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_CLOSE_STMT_NAME.str,AUDIT_CLOSE_STMT_NAME.length))
    {
      strmake(op_str, AUDIT_CLOSE_STMT_NAME.str,AUDIT_CLOSE_STMT_NAME.length);
    }
    /* The reset statement operation*/
    else if((opt_audit_ops &AUDIT_RESET_STMT)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_RESET_STMT_NAME.str,AUDIT_RESET_STMT_NAME.length))
    {
      strmake(op_str, AUDIT_RESET_STMT_NAME.str,AUDIT_RESET_STMT_NAME.length);
    }
    /* The set option operation*/
    else if((opt_audit_ops & AUDIT_SET_OPTION)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_SET_OPTION_NAME.str,AUDIT_SET_OPTION_NAME.length))
    {
      strmake(op_str, AUDIT_SET_OPTION_NAME.str,AUDIT_SET_OPTION_NAME.length);
    }
    /* The fetch operation*/
    else if((opt_audit_ops & AUDIT_FETCH)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_FETCH_NAME.str,AUDIT_FETCH_NAME.length))
    {
      strmake(op_str, AUDIT_FETCH_NAME.str,AUDIT_FETCH_NAME.length);
    }
    /* The daemon operation*/
    else if((opt_audit_ops & AUDIT_DAEMON)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_DAEMON_NAME.str,AUDIT_DAEMON_NAME.length))
    {
      strmake(op_str, AUDIT_DAEMON_NAME.str,AUDIT_DAEMON_NAME.length);
    }
    /* The error operation*/
    else if((opt_audit_ops & AUDIT_ERROR)&& 
      !strncasecmp(my_event_gen->general_command,AUDIT_ERROR_NAME.str,AUDIT_ERROR_NAME.length))
    {
      strmake(op_str, AUDIT_ERROR_NAME.str,AUDIT_ERROR_NAME.length);
    }
    DBUG_RETURN(op_str);
  }

  /*
  Prepare the connect operations for current connect.

  SYNOPSIS
  prepare_general_ops()
  my_event_gen    The mysql event general object   
  op_str                The general operation string type.

  DESCRIPTION
  Prepare the connect operations for current query.
  */
  char* prepare_connect_ops(struct mysql_event_connection *my_event_con, char* op_str)
  {
    DBUG_ENTER("prepare_connect_ops");
    switch (my_event_con->event_subclass)
    {
    case MYSQL_AUDIT_CONNECTION_CONNECT:
      if (opt_audit_ops&AUDIT_CONNECT)  
      {
        strmake(op_str, AUDIT_CONNECT_NAME.str,AUDIT_CONNECT_NAME.length);         
      }
      break;
    case MYSQL_AUDIT_CONNECTION_DISCONNECT: 
      if(opt_audit_ops&AUDIT_QUIT)
      {
        strmake(op_str, AUDIT_QUIT_NAME.str,AUDIT_QUIT_NAME.length);   
      }
      break;
    case MYSQL_AUDIT_CONNECTION_CHANGE_USER:  
      if(opt_audit_ops&AUDIT_CHANGE_USER)
      {
        strmake(op_str, AUDIT_CHANGE_USER_NAME.str,AUDIT_CHANGE_USER_NAME.length);   
      }
      break;
    default:
      break;
    }
    DBUG_RETURN(op_str);
  }


  /*
  Erase the password value from '\'' or '\"' to the end  '\'' or '\"'.

  SYNOPSIS
  erase()
  password    The password string   

  DESCRIPTION
  Erase the password.
  */
  static inline void erase(char* password)
  {
    for(; password && *password!='\'' && *password!='\"';password++);
    password++;

    while (password && *password!='\'' && *password!='\"')
    {
      *(password++) = '#'; 
    }
  }

  /*
  Erase the password from the query string.

  SYNOPSIS
  erase_password()
  op_str        The general operation string type
  query          The query string.

  DESCRIPTION
  Erase the password from the query if the current query involved password. 
  If the op_str is grant statement, the password after the "by" keywords, then
  replace the password after "by" into '*'. 
  The other cases are not recommended, but the process procedures is needed.
  The other cases involve the operations directly modified the table of MYSQL.USER 
  and the set the PASSWORD for the given user.
  */
  char*  erase_password(MYSQL_THD thd,char* op_str,const char* query)
  {
    char* pos;
    char* pre,* post;
    char *token_key, *last_key, *token_value,*last_value;
    char* local_query;
    TABLE_LIST* table_list;
    int num=0;
    DBUG_ENTER("erase_password");
    local_query = (char*)strdup(query);
    if (!local_query)
    {
      DBUG_PRINT("error",("Duplicating the query string failed!"));
      DBUG_RETURN(NullS);
    }   

    /* The following procedure process the operations of grant privileges 
    * and set the password.
    * exp: GRANT ALL ON *.* to ''@'' IDENTIFIED BY '###'
    */
    if (!strncasecmp(op_str,AUDIT_GRANT_NAME.str,AUDIT_GRANT_NAME.length))
    {
      pos = strstr(local_query,KEY_BY);
      if (pos && (pos+=3))
      {
        erase(pos);     
      }   
      DBUG_RETURN(local_query);
    }else if(!strncasecmp(op_str,AUDIT_SET_NAME.str,AUDIT_SET_NAME.length))
    {
      /* The following procedure process the operations of grant privileges 
      * and set the password.
      * exp: SET PASSWORD FOR ''@"" = PASSWORD('###');
      */
      pos = strstr(local_query,PASSWORD_NAME.str);
      if (pos)
      {
        erase(pos);
      }         
      DBUG_RETURN(local_query);
    }else{
      /* The following procedure process the operations which directly 
      * modify the data through the table of mysql.user. The examples 
      * like the exp1 and exp2.
      * exp1:  REPLACE INTO mysql.user (Host,User,Password) 
      *                 VALUES('','',PASSWORD('###')); 
      * exp2:  INSERT INTO mysql.user (Host,User,Password) 
      *                  VALUES('','',PASSWORD('###'));   
      * exp3:  INSERT INTO mysql.user VLAUES('','','###',...);
      * exp4:  INSERT INTO user VALUES('','','###',...);
      * exp5:  UPDATE user SET Password=PASSWORD("###") where user=""; 
      */
      /*Check the database is mysql and the table is user or the table name is mysql.user*/

      for(table_list = thd->lex->query_tables; table_list &&  
        (strncasecmp((const char*)table_list->db,MYSQL_SCHEMA_NAME.str,MYSQL_SCHEMA_NAME.length) ||
        strncasecmp((const char*)table_list->table_name,USER_NAME.str,USER_NAME.length));
      table_list = table_list->next_local);  

      if(!table_list)
        DBUG_RETURN(local_query);

      pos = strstr(local_query,MYSQL_USER_NAME.str);
      if (!pos)
      {
        pos = strstr(local_query,USER_NAME.str);
        if(!pos)
          DBUG_RETURN(local_query);
        for(pos+=USER_NAME.length;pos && *pos==' ';pos++);
      }else
        for(pos+=MYSQL_USER_NAME.length;pos && *pos==' ';pos++);

      /* The format like exp1 or exp2*/
      if (*pos == '(')
      {
        pre = strstr(pos+1,"(");
        if (pre)
        {
          post = pre+1;
          *pre='\0';

          token_key = strtok_r(pos+1,DELIM_KEY,&last_key);
          token_value = strtok_r(post,DELIM_KEY,&last_value);

          while (token_key && strncasecmp(token_key,PASSWORD_NAME.str,PASSWORD_NAME.length))
          {
            *(last_key-1) = ',';
            *(last_value -1) = ',';
            token_key = strtok_r(NULL,DELIM_KEY,&last_key);
            token_value = strtok_r(NULL,DELIM_KEY,&last_value);
            for(;token_key && *token_key==' ';token_key++);
            for(;token_value && *token_value==' ';token_value++);
          }         
          if (token_key && token_value)
          {
            erase(token_value);                         
          }
          if (strlen(last_key)!=0)
          {
            *(last_key-1) = ',';
            *(last_value -1) = ',';
          }
          *pre = '(';
        }       
      }
      /* The format like exp3 or exp4*/
      else{
        pre = strstr(pos +1,PASSWORD_NAME.str);
        /* The format like exp4 */
        if (pre)
        {
          erase(pre);
        }
        /* The format like exp3 */
        else{
          pre = strstr(pos+1,"(");
          token_value = strtok_r(pre,DELIM_KEY,&last_value);
          while (token_value && ++num < PWD_COLUMN)
          {
            *(last_value-1) = ',';
            token_value = strtok_r(NULL,DELIM_KEY, &last_value);
          }
          if (token_value)
          {
            erase(token_value);
          }
          *(last_value-1) = ',';
        }
      }
    }
    DBUG_RETURN(local_query);
  }

  /*
  Initialize the default value of variables .

  SYNOPSIS
  init_default_vars()

  RETURN VALUE
  0                    success
  1                    failure (cannot happen)
  */
  static int init_default_vars()
  {
    DBUG_ENTER("init_default_vars");
    opt_audit_file_size = 0;
    opt_audit_ops = 0;
    opt_audit_class = LOG_FILE;
    opt_audit_users = 0;
    opt_audit_dbs = 0;
    opt_audit_tables = 0;
    opt_ignore_users = 0;
    opt_ignore_dbs = 0;
    opt_ignore_tables = 0;
    opt_audit_dir = 0;
    opt_audit_file = 0;
    strmake(default_audit_dir,mysql_real_data_home,FN_REFLEN);
    strmake(default_audit_filename,"mysql-audit",FN_REFLEN);
    /* Initialize the dynamic array of audit user. */
    if((audit_users = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME))))
    {
      if(init_dynamic_array(audit_users,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        DBUG_PRINT("error",("Initalize the dynamic array of users failed."));
        DBUG_RETURN(1);
      }
    }
    /* Initialize the dynamic array of audit database. */
    if((audit_dbs = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME))))
    {
      if(init_dynamic_array(audit_dbs,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        DBUG_PRINT("error",("Initalize the dynamic array of users failed."));
        DBUG_RETURN(1);
      }
    }
    /* Initialize the dynamic array of audit tables. */
    if((audit_tables = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME))))
    {
      if(init_dynamic_array(audit_tables,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        DBUG_PRINT("error",("Initalize the dynamic array of users failed."));
        DBUG_RETURN(1);
      }
    } 
    /* Initialize the dynamic array of ignore user. */
    if((ignore_users = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME))))
    {
      if(init_dynamic_array(ignore_users,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        DBUG_PRINT("error",("Initalize the dynamic array of users failed."));
        DBUG_RETURN(1);
      }
    }
    /* Initialize the dynamic array of audit database. */
    if((ignore_dbs = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME))))
    {
      if(init_dynamic_array(ignore_dbs,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        DBUG_PRINT("error",("Initalize the dynamic array of users failed."));
        DBUG_RETURN(1);
      }
    }
    /* Initialize the dynamic array of audit tables. */
    if((ignore_tables = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME))))
    {
      if(init_dynamic_array(ignore_tables,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        DBUG_PRINT("error",("Initalize the dynamic array of users failed."));
        DBUG_RETURN(1);
      }
    } 
    DBUG_RETURN(0);
  }

  /*
  Convert the value with digit unit to unsigned long long value.
  The digit unit involved K,KB,M,MB,G,GB. 

  SYNOPSIS
  convert_digit_unit()
  value     The value for converting.

  RETURN VALUE
  The value of converted.
  */
  static ulonglong convert_digit_unit(char* value)
  {
    char *ptr;
    ulonglong temp = 0;
    ulonglong res;
    DBUG_ENTER("convert_digit_unit");
    int len = strlen(value);
    ptr = value+len-1;
    /* The value has unit. */
    if (ptr != value && !isdigit(*ptr) )
    { 
      /*Check the type of G/M/K to set the real size*/
      for(;!isdigit(*ptr);ptr--) ;
      ptr++;
      /* The unit is K or KB. */
      if(!strncasecmp(ptr,K_TYPE, strlen(K_TYPE)) || 
        !strncasecmp(ptr,KB_TYPE,strlen(KB_TYPE)))
      {
        *ptr = '\0';
        temp = strtoull(value, NULL, 0);
        res = (ulonglong)(temp < ULLONG_MAX /KB_SIZE)? temp*KB_SIZE : 0;
      }
      /* The unit is M or MB. */
      else if(!strncasecmp(ptr,M_TYPE, strlen(M_TYPE)) || 
        !strncasecmp(ptr,MB_TYPE,strlen(MB_TYPE)))
      {
        *ptr = '\0';
        temp = strtoull(value, NULL, 0);
        res = (ulonglong) (temp < ULLONG_MAX/MB_SIZE)? temp*MB_SIZE:0;
      }
      /* The unit is G or GB. */
      else if(!strncasecmp(ptr,G_TYPE,strlen(G_TYPE)) || 
        !strncasecmp(ptr,GB_TYPE,strlen(GB_TYPE)))
      {
        *ptr = '\0';
        temp = strtoull(value, NULL, 0);
        res =(ulonglong) (temp < ULLONG_MAX/GB_SIZE)? temp*GB_SIZE:0;
      }
      /* The unit is invalid. */
      else{
        DBUG_PRINT("error",("The value: %s is invalid. Please be double check the variable.",value));
        DBUG_RETURN(0);
      }
    }
    /* The value has not unit, then convert the string to long*/
    else
    {
      res =strtoull(value, NULL, 0);
    } 
    DBUG_RETURN(res);
  }

  /*
  Convert the audit_class with char to int value, and the 
  audit_class can be FILE,TABLE, 1,2.

  SYNOPSIS
  convert_audit_class()
  value    The value for converting

  RETURN VALUE
  1           FILE
  2           TABLE
  */
  static uint convert_audit_class(char* value)
  {
    DBUG_ENTER("convert_audit_class");
    if (!strncasecmp(value,LOG_TABLE_STR,strlen(LOG_TABLE_STR)))  
      DBUG_RETURN( (uint) LOG_TABLE); 
    else if(isdigit(*value) && atoi(value) == LOG_TABLE)
      DBUG_RETURN( (uint) LOG_TABLE); 
    DBUG_RETURN((uint) LOG_FILE); 
  }

  /*
  Convert the char with on/off to bool value, and the 
  char value can be FILE,TABLE, 1,0.

  SYNOPSIS
  convert_char_bool()
  value     The value for converting.

  RETURN VALUE
  TRUE          The value is on or 1  
  FALSE         The vallue is off or 0
  */
  static my_bool convert_char_bool(char* value)
  {
    DBUG_ENTER("convert_char_bool");
    if (!strncasecmp(value,ON_STATUS,strlen(ON_STATUS)))
    {
      DBUG_RETURN(TRUE);  
    }else if (isdigit(*value))
    {
      DBUG_RETURN(atoi(value)?TRUE:FALSE);
    }
    DBUG_RETURN(FALSE);
  }

  /*
  The implementation of the callback function cb_init_config_vars() 
  to initialize the global variables according to the configure file.

  SYNOPSIS
  init_config_vars()
  key                The vairable name
  value              The variable value
  group             The variable group name.

  RETURN VALUE
  0                    success
  1                    failure (cannot happen)
  */
  static int init_config_vars(char* key, char* value, char* group)
  {
    DBUG_ENTER("init_config_vars");
    if (!key)
    {
      DBUG_PRINT("error",("The key value is NULL"));
      DBUG_RETURN(-1);
    }
    /* If the key is a group, check the group is invalid or not*/
    if (key==group ){
      if(!strncasecmp(group,AUDIT_GROUP,strlen(AUDIT_GROUP)))
        DBUG_RETURN(0);
      else
        DBUG_RETURN(1); 
    } 
    int idx = 0; 
    for (;default_options[idx] && (strncasecmp(default_options[idx],key,max(strlen(key),strlen(default_options[idx]))));idx++) ; 
    if (idx > CMD_NUM)
    {
      DBUG_PRINT("error",("The key: %s is invalid",key));
      DBUG_RETURN(1);
    } 
    /* Set the value of global variables. */
    switch(idx){
  case VAR_DIR:
    opt_audit_dir = strdup(value);
    break;
  case VAR_FILE:
    opt_audit_file = strdup(value);
    break;
  case VAR_FILE_SIZE:
    opt_audit_file_size = convert_digit_unit(value);
    break;
  case VAR_USERS:
    opt_audit_users = strdup(value);
    break;
  case VAR_DBS:
    opt_audit_dbs = strdup(value);
    break;
  case VAR_TABLES:
    opt_audit_tables = strdup(value);
    break;
  case VAR_IGNORE_USERS:
    opt_ignore_users = strdup(value);
    break;
  case VAR_IGNORE_DBS:
    opt_ignore_dbs = strdup(value);
    break;
  case VAR_IGNORE_TABLES:
    opt_ignore_tables = strdup(value);
    break;
  case VAR_CLASS:
    opt_audit_class = convert_audit_class(value);
    break;
  case VAR_OPS:
    opt_audit_ops = strtoull(value, NULL, 0);
    break;
  case VAR_ALL:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_ALL;
    else
      opt_audit_ops &= ~AUDIT_ALL;
    break;
  case VAR_FULL:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_FULL;
    else
      opt_audit_ops &= ~AUDIT_FULL;
    break;
  case VAR_CMD:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_CMD;
    else
      opt_audit_ops &= ~AUDIT_CMD;
    break;
  case VAR_CREATE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_CREATE;
    else
      opt_audit_ops &= ~AUDIT_CREATE;
    break;
  case VAR_DROP:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DROP;
    else
      opt_audit_ops &= ~AUDIT_DROP;
    break;
  case VAR_ALTER:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_ALTER;
    else
      opt_audit_ops &= ~AUDIT_ALTER;
    break;
  case VAR_DDL:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DDL;
    else
      opt_audit_ops &= ~AUDIT_DDL;
    break;
  case VAR_INSERT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_INSERT;
    else
      opt_audit_ops &= ~AUDIT_INSERT;
    break;
  case VAR_DELETE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DELETE;
    else
      opt_audit_ops &= ~AUDIT_DELETE;
    break;
  case VAR_UPDATE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_UPDATE;
    else
      opt_audit_ops &= ~AUDIT_UPDATE;
    break;
  case VAR_REPLACE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_REPLACE;
    else
      opt_audit_ops &= ~AUDIT_REPLACE;
    break;
  case VAR_MODIFY:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_MODIFY;
    else
      opt_audit_ops &= ~AUDIT_MODIFY;
    break;
  case VAR_SELECT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_SELECT;
    else
      opt_audit_ops &= ~AUDIT_SELECT;
    break;
  case VAR_DML:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DML;
    else
      opt_audit_ops &= ~AUDIT_DML;
    break;
  case VAR_GRANT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_GRANT;
    else
      opt_audit_ops &= ~AUDIT_GRANT;
    break;
  case VAR_REVOKE:
    if(convert_char_bool(value))
      opt_audit_ops |=AUDIT_REVOKE;
    else
      opt_audit_ops &= ~AUDIT_REVOKE;
    break;
  case VAR_DCL:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DCL;
    else
      opt_audit_ops &= ~AUDIT_DCL;
    break;
  case VAR_SET:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_SET;
    else
      opt_audit_ops &= ~AUDIT_SET;
    break;
  case VAR_CONNECT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_CONNECT;
    else
      opt_audit_ops &= ~AUDIT_CONNECT;
    break;
  case VAR_QUIT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_QUIT;
    else
      opt_audit_ops &= ~AUDIT_QUIT;
    break;
  case VAR_CHANGE_USER:
    if(convert_char_bool(value))
      opt_audit_ops |=AUDIT_CHANGE_USER;
    else
      opt_audit_ops &= ~AUDIT_CHANGE_USER;
    break;
  case VAR_CONNECTION:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_CONNECTION;
    else
      opt_audit_ops &= ~AUDIT_CONNECTION;
    break;
  case VAR_SERVER:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_SERVER;
    else
      opt_audit_ops &= ~AUDIT_SERVER;
    break;
  case VAR_SLEEP:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_SLEEP;
    else
      opt_audit_ops &= ~AUDIT_SLEEP;
    break;
  case VAR_INIT_DB:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_INIT_DB;
    else
      opt_audit_ops &= ~AUDIT_INIT_DB;
    break;
  case VAR_FIELD_LIST:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_FIELD_LIST;
    else
      opt_audit_ops &= ~AUDIT_FIELD_LIST;
    break;
  case VAR_REFRESH:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_REFRESH;
    else
      opt_audit_ops &= ~AUDIT_REFRESH;
    break;
  case VAR_SHUTDOWN:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_SHUTDOWN;
    else
      opt_audit_ops &= ~AUDIT_SHUTDOWN;
    break;
  case VAR_STATISTICS:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_STATISTICS;
    else
      opt_audit_ops &= ~AUDIT_STATISTICS;
    break;
  case VAR_PROCESSLIST:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_PROCESSLIST;
    else
      opt_audit_ops &= ~AUDIT_PROCESSLIST;
    break;
  case VAR_KILL:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_KILL;
    else
      opt_audit_ops &= ~AUDIT_KILL;
    break;
  case VAR_DEBUG:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DEBUG;
    else
      opt_audit_ops &= ~AUDIT_DEBUG;
    break;
  case VAR_PING:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_PING;
    else
      opt_audit_ops &= ~AUDIT_PING;
    break;
  case VAR_TIME:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_TIME;
    else
      opt_audit_ops &= ~AUDIT_TIME;
    break;
  case VAR_DELAY_INSERT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DELAY_INSERT;
    else
      opt_audit_ops &= ~AUDIT_DELAY_INSERT;
    break;
  case VAR_BINLOG_DUMP:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_BINLOG_DUMP;
    else
      opt_audit_ops &= ~AUDIT_BINLOG_DUMP;
    break;
  case VAR_TABLE_DUMP:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_TABLE_DUMP;
    else
      opt_audit_ops &= ~AUDIT_TABLE_DUMP;
    break;
  case VAR_CONNECT_OUT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_CONNECT_OUT;
    else
      opt_audit_ops &= ~AUDIT_CONNECT_OUT;
    break;
  case VAR_REGISTER_SLAVE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_REGISTER_SLAVE;
    else
      opt_audit_ops &= ~AUDIT_REGISTER_SLAVE;
    break;
  case VAR_PREPARE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_PREPARE;
    else
      opt_audit_ops &= ~AUDIT_PREPARE;
    break;
  case VAR_EXECUTE:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_EXECUTE;
    else
      opt_audit_ops &= ~AUDIT_EXECUTE;
    break;
  case VAR_LONG_DATA:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_LONG_DATA;
    else
      opt_audit_ops &= ~AUDIT_LONG_DATA;
    break;
  case VAR_CLOSE_STMT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_CLOSE_STMT;
    else
      opt_audit_ops &= ~AUDIT_CLOSE_STMT;
    break;
  case VAR_RESET_STMT:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_RESET_STMT;
    else
      opt_audit_ops &= ~AUDIT_RESET_STMT;
    break;
  case VAR_SET_OPTION:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_SET_OPTION;
    else
      opt_audit_ops &= ~AUDIT_SET_OPTION;
    break;
  case VAR_FETCH:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_FETCH;
    else
      opt_audit_ops &= ~AUDIT_FETCH;
    break;
  case VAR_DAEMON:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_DAEMON;
    else
      opt_audit_ops &= ~AUDIT_DAEMON;
    break;
  case VAR_ERROR:
    if(convert_char_bool(value))
      opt_audit_ops |= AUDIT_ERROR;
    else
      opt_audit_ops &= ~AUDIT_ERROR;
    break;
  default:
    break;
    } 
    DBUG_RETURN(0);
  }
  /*
  Convert the databases of current query used into string.

  SYNOPSIS
  databases_to_string()
  thd                    The MYSQL_THD.
  dbs_buf            The string buffer.

  RETURN VALUE
  The point of dbs_buf.
  */
char* databases_to_string(MYSQL_THD thd, char* dbs_buf)
{
  TABLE_LIST* table_list;
  char* pos = dbs_buf;
  DBUG_ENTER("databases_to_string");
  for(table_list = thd->lex->query_tables;
    table_list && table_list->db; table_list = table_list->next_local)
  {
    snprintf(pos, BUF_LEN, "%s,",table_list->db);
    pos +=strlen(dbs_buf);
  }
  *(--pos)='\0';
  DBUG_RETURN(dbs_buf);
}

  /*
  Check the object whether in the Dynamic array or not.

  SYNOPSIS
  check_object()
  array              The the dynamic array.
  object            The object for check.

  RETURN VALUE
  TRUE                    success
  FALSE                   failure 
  */
  static my_bool check_object(DYNAMIC_ARRAY* array, const char* object)
  {
    uint idx=0;
    char element[FN_LEN]={0};
    for (idx = 0;idx < array->elements;idx++)
    {
      get_dynamic(array,(uchar*)element,idx);
      if (!strncasecmp((const char*)element,KEY_ALL,strlen(KEY_ALL)) || 
        !strncasecmp((const char*)element,object,strlen(element)))
      {
        return TRUE;
      }   
    }
    return FALSE;
  }

  /*
  Check the user whether in the Dynamic array or not.

  SYNOPSIS
  check_users()
  users              The the dynamic array.
  user                The user for check.

  RETURN VALUE
  TRUE                    success
  FALSE                   failure 
  */
  my_bool check_users(MYSQL_THD thd)
  {
    
    /**
     * Check the query users whether in ignore users. If 
     * the current query user in the ignore users, the return 
     * result is FALSE, then the operation will not be audited.
     */
    if(check_object(ignore_users,thd->main_security_ctx.user))
      return FALSE;
    /**
     * Check the current query user whether in audit users
     * or not. 
     */
    return check_object(audit_users,thd->main_security_ctx.user);
  }

  /*
  Check the user whether in the Dynamic array or not.

  SYNOPSIS
  check_databases()
  users              The the dynamic array.
  user                The user for check.

  RETURN VALUE
  TRUE                    success
  FALSE                   failure 
  */
  my_bool check_databases(MYSQL_THD thd)
  {
    TABLE_LIST* table_list;
    my_bool flag = FALSE;
    for(table_list = thd->lex->query_tables;
      table_list; table_list = table_list->next_local)
    {
      /**
      * Check the query databases whether in ignore databases. If 
      * the current query database in the ignore databases, the return 
      * result is FALSE, then the operation will not be audited.
      */
      if(check_object(ignore_dbs,table_list->db))
        return FALSE;
      /**
      * Check the current query database whether in audit databases
      * or not. If the query database has been in the audit database,
      * will not be continued to check the database. Or check the 
      * database whether in audit databases.
      */
      if(!flag && check_object(audit_dbs,table_list->db))
        flag = TRUE;
    }
    return flag;
  }

  /*
  Check the user whether in the Dynamic array or not.

  SYNOPSIS
  check_tables()
  users              The the dynamic array.
  user                The user for check.

  RETURN VALUE
  TRUE                    success
  FALSE                   failure 
  */
  my_bool check_tables(MYSQL_THD thd)
  {
    TABLE_LIST* table_list;
    uint idx=0;
    char element[FN_LEN]={0};
    char* pos;
    size_t db_len=0,tbl_len=0;
    /**
     * Check the used table whether in ignore tables or not. If the 
     * current query table in the ignore tables, the return result is 
     * FALSE, then operation will not be audited. Or, check the 
     * query tables whether in audit tables or not.
     */
    for (idx = 0;idx < ignore_tables->elements;idx++)
    {
      get_dynamic(ignore_tables,(uchar*)element,idx);
      pos = strstr(element,".");
      if(!pos)
        break;
      db_len = pos - element;
      pos++;
      tbl_len = strlen(element)-db_len-1;
      for(table_list = thd->lex->query_tables; table_list; table_list = table_list->next_local)
      {
        if ((!strncasecmp((const char*)element,KEY_ALL,max(db_len,strlen(KEY_ALL))) || 
          !strncasecmp((const char*)element,table_list->db,max(db_len,strlen(table_list->db))))&&
          (!strncasecmp((const char*)pos,KEY_ALL,max(tbl_len,strlen(KEY_ALL))) || 
          !strncasecmp((const char*)pos, table_list->table_name,max(tbl_len,strlen(table_list->table_name)))))
          return FALSE;        
      }
    }
    /**
     *Check the used tables whether in audit tables or not.
     */
    for (idx = 0;idx < audit_tables->elements;idx++)
    {
      get_dynamic(audit_tables,(uchar*)element,idx);
      pos = strstr(element,".");
      if(!pos)
        return FALSE;
      db_len = pos - element;
      pos++;
      tbl_len = strlen(element)-db_len-1;
      for(table_list = thd->lex->query_tables; table_list; table_list = table_list->next_local)
      {
        if ((!strncasecmp((const char*)element,KEY_ALL,max(db_len,strlen(KEY_ALL))) || 
          !strncasecmp((const char*)element,table_list->db,max(db_len,strlen(table_list->db))))&&
          (!strncasecmp((const char*)pos,KEY_ALL,max(tbl_len,strlen(KEY_ALL))) || 
          !strncasecmp((const char*)pos, table_list->table_name,max(tbl_len,strlen(table_list->table_name)))))
          return TRUE;        
      }
    }
    return FALSE;
  }


  /*
  Split the string src which separated by ',' and store the element into
  dynamic array.

  SYNOPSIS
  split_format_string()
  src                   The string to be scanned.
  audit_array        The dynamic array to store the element  separated by ','

  RETURN VALUE
  0                    success
  1                   failure 
  */
  static int split_format_string(char* src, DYNAMIC_ARRAY* audit_array)
  {
    char * token,*last;
    char buf[FN_LEN]={0};
    DBUG_ENTER("split_format_string");  

    token = strtok_r(src,DELIM_KEY,&last);

    while(token)
    {
      strmake(buf,token,FN_LEN);
      if(insert_dynamic(audit_array,(uchar*)buf))
      {
        DBUG_PRINT("error",("Can't insert the value :%s into dynamic array.",buf));
        DBUG_RETURN(1);   
      }
      token = strtok_r(NULL,DELIM_KEY,&last);
    }
    DBUG_RETURN(0); 
  }

  /*
  Initialize the plugin at server start or plugin installation.

  SYNOPSIS
  audit_plugin_init()

  DESCRIPTION
  Initialized the file handler for auditting and the 
  commands number of localhost

  RETURN VALUE
  0                    success
  1                    failure 
  */
  static int audit_plugin_init(void *arg __attribute__((unused)))
  {
    DBUG_ENTER("audit_plugin_init");
    //commands=0;
    /* Initialize the default variables. */
    if(init_default_vars())
    {
      DBUG_PRINT("error",("Initialized the default variables failed."));
      DBUG_RETURN(1);
    } 
    if (!my_stat(config_file,&config_stat,MYF(0)))
    {
      DBUG_PRINT("error",("Get the status of file: %s failed.",
        config_file));
      DBUG_RETURN(1);
    }  
    /* Parse the configure file, callback the init_config_vars function to parse the vairables. */
    if(parse_config_file(config_file,init_config_vars))
      DBUG_RETURN(1);
    if (!opt_audit_dir)
    {
      opt_audit_dir = strdup(default_audit_dir);
    }
    if(!opt_audit_file)
    {
      opt_audit_file = strdup(default_audit_filename);
    } 
    if(!opt_audit_users)
    {
      opt_audit_users = strdup(ALL_USERS);
    }
    /* Split the audit users and store into the dynamic array. */
    if (opt_audit_users)
    {
      if(split_format_string(opt_audit_users,  audit_users))
      {
        DBUG_PRINT("error",("Failed when splitting format string :"
          "%s .",opt_audit_users));
        DBUG_RETURN(1);
      }
    }
    if(!opt_audit_dbs)
    {
      opt_audit_dbs = strdup(ALL_DBS);
    }
    /* Split the audit databases and store into the dynamic array. */
    if(opt_audit_dbs)
    {
      if(split_format_string(opt_audit_dbs,  audit_dbs))
      {
        DBUG_PRINT("error",("Failed when splitting format string :"
          "%s .",opt_audit_dbs));
        DBUG_RETURN(1);
      }
    }
    if(!opt_audit_tables)
    {
      opt_audit_tables = strdup(ALL_TABLES);
    }
    /* Split the audit tables and store into the dynamic array. */
    if(opt_audit_tables)
    {
      if(split_format_string(opt_audit_tables,  audit_tables))
      {
        DBUG_PRINT("error",("Failed when splitting format string :"
          "%s .",opt_audit_tables));
        DBUG_RETURN(1);
      }
    }
    if(!opt_ignore_users)
    {
      opt_ignore_users = strdup(EMPTY_KEY);
    }
    /* Split the ingore users and store into the dynamic array. */
    if(opt_ignore_users)
    {
      if(split_format_string(opt_ignore_users,  ignore_users))
      {
        DBUG_PRINT("error",("Failed when splitting format string :"
          "%s .",opt_ignore_users));
        DBUG_RETURN(1);
      }
    }
    if(!opt_ignore_dbs)
    {
      opt_ignore_dbs = strdup(EMPTY_KEY);
    }
    /* Split the ignore databases and store into the dynamic array. */
    if(opt_ignore_dbs)
    {
      if(split_format_string(opt_ignore_dbs,  ignore_dbs))
      {
        DBUG_PRINT("error",("Failed when splitting format string :"
          "%s .",opt_ignore_dbs));
        DBUG_RETURN(1);
      }
    }
    if(!opt_ignore_tables)
    {
      opt_ignore_tables = strdup(EMPTY_KEY);
    }
    /* Split the ignore tables and store into the dynamic array. */
    if(opt_ignore_tables)
    {
      if(split_format_string(opt_ignore_tables,  ignore_tables))
      {
        DBUG_PRINT("error",("Failed when splitting format string :"
          "%s .",opt_ignore_tables));
        DBUG_RETURN(1);
      }
    }
    /* Based on the audit class, initialized the audit file or table.*/
    switch(opt_audit_class){
  case LOG_FILE:
    if(init_audit_file())
      DBUG_RETURN(1);
    break;
  case LOG_TABLE:
    if(init_audit_table())
      DBUG_RETURN(1);
    break;
    }
    DBUG_RETURN(0);
  }

  /*
  Terminate the plugin at server shutdown or plugin deinstallation.

  SYNOPSIS
  audit_file_plugin_deinit()
  Does nothing.

  RETURN VALUE
  0                    success
  1                    failure (cannot happen)
  */

  static int audit_plugin_deinit(void *arg __attribute__((unused)))
  {
    DBUG_ENTER("audit_plugin_deinit");
    if (opt_audit_file)
    {
      free(opt_audit_file);
    }
    if(opt_audit_dir)
    {
      free(opt_audit_dir);
    }
    if (audit_users)
    {
      delete_dynamic(audit_users);
      my_free(audit_users);
    }
    if(opt_audit_users)
    {
      free(opt_audit_users);
    }
    if(opt_audit_dbs)
    {
      free(opt_audit_dbs);
    }
    if(audit_dbs)
    {
      delete_dynamic(audit_dbs);
      my_free(audit_dbs);
    }
    if(opt_audit_tables)
    {
      free(opt_audit_tables);
    }
    if(audit_tables)
    {
      delete_dynamic(audit_tables);
      my_free(audit_tables);
    }
    if(opt_ignore_users)
    {
      free(opt_ignore_users);
    }
    if(ignore_users)
    {
      delete_dynamic(ignore_users);
      my_free(ignore_users);
    }
    if(opt_ignore_dbs)
    {
      free(opt_ignore_dbs);
    }
    if(ignore_dbs)
    {
      delete_dynamic(ignore_dbs);
      my_free(ignore_dbs);
    }
    if(opt_ignore_tables)
    {
      free(opt_ignore_tables);
    }
    if(ignore_tables)
    {
      delete_dynamic(ignore_tables);
      my_free(ignore_tables);
    }
    /* Based on the audit class, deinitialized the audit file or table.*/
    switch(opt_audit_class){
  case LOG_FILE:
    deinit_audit_file();
    break;
  case LOG_TABLE:
    deinit_audit_table();
    break;
    }
    DBUG_RETURN(0);
  }

  /*
  Audit the operations information into file.

  SYNOPSIS
  audit_notify()
  thd                Connection context
  event_class    The event class: general or connect
  event             The event object.

  DESCRIPTION
  If the current operation is connection, audit it. 
  */
  static void audit_notify(MYSQL_THD thd ,
    unsigned int event_class,
    const void *event)
  { 
    MY_STAT current_stat;
    DBUG_ENTER("audit_notify"); 
    if (!my_stat(config_file,&current_stat,MYF(0)))
    {
      DBUG_PRINT("error",("Get the status of file: %s failed.",
        config_file));
      DBUG_VOID_RETURN;
    }  
    /* If the configure file modified, then reload the configure file*/
    if (current_stat.st_mtime!=config_stat.st_mtime)
    {
      audit_plugin_deinit(NULL);
      audit_plugin_init(NULL);
    }
    /* Based on the audit class, audit the operations into file or table.*/
    switch(opt_audit_class){
  case LOG_FILE:
    if(!audit_file_notify(thd,event_class,event)){
      commands++;
    }else
      DBUG_PRINT("warning",("Audit the operation into file failed."));
    break;
  case LOG_TABLE:
    if(!audit_table_notify(thd,event_class,event)){   
      commands++;
    } else
      DBUG_PRINT("warning",("Audit the operation into table failed."));
    break;
  default:
    break;
    }

    DBUG_VOID_RETURN;
  }


  /*
  Plugin type-specific descriptor
  */

  static struct st_mysql_audit audit_descriptor=
  {
    MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
    NULL,                                             /* release_thd function */
    audit_notify,                                /* notify function      */
    { (unsigned long) (MYSQL_AUDIT_GENERAL_CLASSMASK | MYSQL_AUDIT_CONNECTION_CLASSMASK) } /* class mask           */
  };

  /*
  Plugin status variables for SHOW STATUS
  */
  static char  audit_file_size_format[FN_LEN]={0};
  static char * format_audit_file_size(ulonglong file_size,char* buf)
  {
    snprintf(buf,FN_LEN,"%lu %s",file_size/MB_SIZE,M_TYPE);
    return buf;
  }
  static struct st_mysql_show_var simple_status[]=
  {
    {"Audit_dir",opt_audit_dir, SHOW_CHAR},
    {"Audit_file",opt_audit_file,SHOW_CHAR},
    {"Audit_file_size",format_audit_file_size(opt_audit_file_size,audit_file_size_format), SHOW_CHAR},
    {"Audit_users",opt_audit_users,SHOW_CHAR},
    {"Audit_dbs",opt_audit_dbs,SHOW_CHAR},
    {"Audit_tables",opt_audit_tables,SHOW_CHAR},
    {"Audit_class",(char*)((opt_audit_class==LOG_TABLE)?LOG_TABLE_STR:LOG_FILE_STR),SHOW_CHAR},
    {"Audit_ops",(char*) &opt_audit_ops,SHOW_LONGLONG},

    {"Audit_all",(char*)((opt_audit_ops&AUDIT_ALL)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_create",(char*)((opt_audit_ops&AUDIT_CREATE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_alter",(char*)((opt_audit_ops&AUDIT_ALTER)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_drop",(char*)((opt_audit_ops&AUDIT_DROP)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_ddl",(char*)((opt_audit_ops&AUDIT_DDL)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_insert",(char*)((opt_audit_ops&AUDIT_INSERT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_update",(char*)((opt_audit_ops&AUDIT_UPDATE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_delete",(char*)((opt_audit_ops&AUDIT_DELETE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_modify",(char*)((opt_audit_ops&AUDIT_MODIFY)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_select",(char*)((opt_audit_ops&AUDIT_SELECT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_dml",(char*)((opt_audit_ops&AUDIT_DML)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_grant",(char*)((opt_audit_ops&AUDIT_GRANT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_revoke",(char*)((opt_audit_ops&AUDIT_REVOKE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_dcl",(char*)((opt_audit_ops&AUDIT_DCL)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_cmd",(char*)((opt_audit_ops&AUDIT_CMD)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_connect",(char*)((opt_audit_ops&AUDIT_CONNECT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_quit",(char*)((opt_audit_ops&AUDIT_QUIT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_change_user",(char*)((opt_audit_ops&AUDIT_CHANGE_USER)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_connection",(char*)((opt_audit_ops&AUDIT_CONNECTION)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_full",(char*)((opt_audit_ops&AUDIT_FULL)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_sleep",(char*)((opt_audit_ops&AUDIT_SLEEP)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_init_db",(char*)((opt_audit_ops&AUDIT_INIT_DB)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_field_list",(char*)((opt_audit_ops&AUDIT_FIELD_LIST)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_refresh",(char*)((opt_audit_ops&AUDIT_REFRESH)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_shutdown",(char*)((opt_audit_ops&AUDIT_SHUTDOWN)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_statistics",(char*)((opt_audit_ops&AUDIT_STATISTICS)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_processlist",(char*)((opt_audit_ops&AUDIT_PROCESSLIST)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_kill",(char*)((opt_audit_ops&AUDIT_KILL)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_debug",(char*)((opt_audit_ops&AUDIT_DEBUG)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_ping",(char*)((opt_audit_ops&AUDIT_PING)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_time",(char*)((opt_audit_ops&AUDIT_TIME)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_delay_insert",(char*)((opt_audit_ops&AUDIT_DELAY_INSERT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_binlog_dump",(char*)((opt_audit_ops&AUDIT_BINLOG_DUMP)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_table_dump",(char*)((opt_audit_ops&AUDIT_TABLE_DUMP)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_connect_out",(char*)((opt_audit_ops&AUDIT_CONNECT_OUT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_register_slave",(char*)((opt_audit_ops&AUDIT_REGISTER_SLAVE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_prepare",(char*)((opt_audit_ops&AUDIT_PREPARE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_execute",(char*)((opt_audit_ops&AUDIT_EXECUTE)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_long_data",(char*)((opt_audit_ops&AUDIT_LONG_DATA)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_close_stmt",(char*)((opt_audit_ops&AUDIT_CLOSE_STMT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_reset_stmt",(char*)((opt_audit_ops&AUDIT_RESET_STMT)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_set_option",(char*)((opt_audit_ops&AUDIT_SET_OPTION)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_fetch",(char*)((opt_audit_ops&AUDIT_FETCH)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_daemon",(char*)((opt_audit_ops&AUDIT_DAEMON)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_error",(char *)((opt_audit_ops&AUDIT_ERROR)? ON_STATUS:OFF_STATUS),SHOW_CHAR},
    {"Audit_commands", (char*)&commands, SHOW_INT},
    { 0, 0, (enum_mysql_show_type)0}
  };

  /*
  Plugin library descriptor
  */
  mysql_declare_plugin(audit)
  {
    MYSQL_AUDIT_PLUGIN,         /* type                            */
      &audit_descriptor,     /* descriptor                      */
      "AUDIT",               /* name                            */
      "heng.wang",              /* author                          */
      "Simple file Audit",        /* description                     */
      PLUGIN_LICENSE_GPL,
      audit_plugin_init,     /* init function (when loaded)     */
      audit_plugin_deinit,   /* deinit function (when unloaded) */
      0x0002,                     /* version                         */
      simple_status,              /* status variables                */
      NULL,                       /* system variables                */
      NULL,
#if MYSQL_VERSION_ID >= 50516
      0,
#endif     
  }
  mysql_declare_plugin_end;

