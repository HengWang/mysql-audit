#ifndef _AUDIT_H
#define _AUDIT_H

/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <my_sys.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <m_string.h>

//Define the string of COMMAND operations.
#define AUDIT_ALL                          (~AUDIT_NONE)     
#define AUDIT_NONE                      (ulonglong) 0

#define AUDIT_CREATE                  (ulonglong) 1
#define AUDIT_ALTER                     (AUDIT_CREATE <<  1)
#define AUDIT_DROP                       (AUDIT_CREATE <<  2)
#define AUDIT_DDL                          (AUDIT_CREATE | AUDIT_ALTER | AUDIT_DROP)

#define AUDIT_INSERT                     (AUDIT_CREATE <<  3)
#define AUDIT_UPDATE                    (AUDIT_CREATE <<  4)
#define AUDIT_REPLACE                  (AUDIT_CREATE << 5)
#define AUDIT_DELETE                     (AUDIT_CREATE <<  6)
#define AUDIT_MODIFY                    (AUDIT_INSERT|AUDIT_UPDATE|AUDIT_DELETE | AUDIT_REPLACE)
#define AUDIT_SELECT                     (AUDIT_CREATE <<  7)
#define AUDIT_DML                           (AUDIT_MODIFY|AUDIT_SELECT)

#define AUDIT_GRANT                      (AUDIT_CREATE <<  8)
#define AUDIT_REVOKE                    (AUDIT_CREATE <<  9)
#define AUDIT_DCL                            (AUDIT_GRANT|AUDIT_REVOKE)

#define AUDIT_SET                            (AUDIT_CREATE << 10)

#define AUDIT_CMD                           (AUDIT_DDL|AUDIT_DML|AUDIT_DCL|AUDIT_SET)

#define AUDIT_CONNECT                 (AUDIT_CREATE <<  11)
#define AUDIT_QUIT                          (AUDIT_CREATE <<  12)
#define AUDIT_CHANGE_USER        (AUDIT_CREATE <<  13)
#define AUDIT_CONNECTION          (AUDIT_CONNECT|AUDIT_QUIT|AUDIT_CHANGE_USER)

#define AUDIT_FULL                         (AUDIT_CMD| AUDIT_CONNECTION)


#define AUDIT_SLEEP                       (AUDIT_CREATE <<  16)
#define AUDIT_INIT_DB                   (AUDIT_CREATE <<  17)
#define AUDIT_FIELD_LIST             (AUDIT_CREATE <<  18)
#define AUDIT_REFRESH                 (AUDIT_CREATE <<  19)
#define AUDIT_SHUTDOWN            (AUDIT_CREATE <<  20)
#define AUDIT_STATISTICS             (AUDIT_CREATE <<  21)
#define AUDIT_PROCESSLIST         (AUDIT_CREATE <<  22)
#define AUDIT_KILL                          (AUDIT_CREATE <<  23)
#define AUDIT_DEBUG                     (AUDIT_CREATE <<  24)
#define AUDIT_PING                         (AUDIT_CREATE <<  25)
#define AUDIT_TIME                         (AUDIT_CREATE  << 26)
#define AUDIT_DELAY_INSERT       (AUDIT_CREATE <<  27)
#define AUDIT_BINLOG_DUMP       (AUDIT_CREATE <<  28)
#define AUDIT_TABLE_DUMP          (AUDIT_CREATE <<  29)
#define AUDIT_CONNECT_OUT       (AUDIT_CREATE <<  30)
#define AUDIT_REGISTER_SLAVE  (AUDIT_CREATE <<  31)
#define AUDIT_PREPARE                 (AUDIT_CREATE <<  32)
#define AUDIT_EXECUTE                (AUDIT_CREATE <<  33)
#define AUDIT_LONG_DATA           (AUDIT_CREATE <<  34)
#define AUDIT_CLOSE_STMT        (AUDIT_CREATE <<  35)
#define AUDIT_RESET_STMT        (AUDIT_CREATE <<  36)
#define AUDIT_SET_OPTION         (AUDIT_CREATE <<  37)
#define AUDIT_FETCH                    (AUDIT_CREATE <<  38)
#define AUDIT_DAEMON                (AUDIT_CREATE <<  39)
#define AUDIT_ERROR                   (AUDIT_CREATE <<  40)

#define AUDIT_SERVER                  (~AUDIT_FULL)
/**
* The audit command name declar
*/
extern LEX_STRING AUDIT_CONNECT_NAME ;    
extern LEX_STRING AUDIT_QUIT_NAME ;   
extern LEX_STRING AUDIT_CHANGE_USER_NAME;    
extern LEX_STRING AUDIT_CREATE_NAME;    
extern LEX_STRING AUDIT_ALTER_NAME;  
extern LEX_STRING AUDIT_DROP_NAME ;  
extern LEX_STRING AUDIT_INSERT_NAME;  
extern LEX_STRING AUDIT_UPDATE_NAME;  
extern LEX_STRING AUDIT_REPLACE_NAME; 
extern LEX_STRING AUDIT_DELETE_NAME ;  
extern LEX_STRING AUDIT_SELECT_NAME ;  
extern LEX_STRING AUDIT_GRANT_NAME  ;  
extern LEX_STRING AUDIT_REVOKE_NAME ;  
extern LEX_STRING AUDIT_SET_NAME; 
extern LEX_STRING AUDIT_SLEEP_NAME;
extern LEX_STRING AUDIT_INIT_DB_NAME;
extern LEX_STRING AUDIT_FIELD_LIST_NAME;
extern LEX_STRING AUDIT_REFRESH_NAME ;
extern LEX_STRING AUDIT_SHUTDOWN_NAME;
extern LEX_STRING AUDIT_STATISTICS_NAME ;
extern LEX_STRING AUDIT_PROCESSLIST_NAME;
extern LEX_STRING AUDIT_KILL_NAME ;
extern LEX_STRING AUDIT_DEBUG_NAME;
extern LEX_STRING AUDIT_PING_NAME;
extern LEX_STRING AUDIT_TIME_NAME ;
extern LEX_STRING AUDIT_DELAY_INSERT_NAME;
extern LEX_STRING AUDIT_BINLOG_DUMP_NAME;
extern LEX_STRING AUDIT_TABLE_DUMP_NAME;
extern LEX_STRING AUDIT_CONNECT_OUT_NAME ;
extern LEX_STRING AUDIT_REGISTER_SLAVE_NAME ;
extern LEX_STRING AUDIT_PREPARE_NAME;
extern LEX_STRING AUDIT_EXECUTE_NAME ;
extern LEX_STRING AUDIT_LONG_DATA_NAME;
extern LEX_STRING AUDIT_CLOSE_STMT_NAME ;
extern LEX_STRING AUDIT_RESET_STMT_NAME;
extern LEX_STRING AUDIT_SET_OPTION_NAME;
extern LEX_STRING AUDIT_FETCH_NAME ;
extern LEX_STRING AUDIT_DAEMON_NAME;
extern LEX_STRING AUDIT_ERROR_NAME ; 


#define KEY_ALL "*"
#define KEY_BY "by"
#define KEY_FROM "from"

#define ALL_USERS KEY_ALL
#define ALL_DBS      KEY_ALL
#define ALL_TABLES KEY_ALL "." KEY_ALL

#define IGNORE_CMD    "/*!"
#define EMPTY_KEY " "
#define QUERY_KEY "Query"

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define FILE_DIR_LEN (FN_REFLEN+DATE_LEN)
#define FILE_NAME_LEN (2*FN_REFLEN+DATE_LEN)

#ifndef INIT_ALLOC_NUM
/* The dynamic allocate and increment number.*/
#define INIT_ALLOC_NUM              10
#endif
#ifndef INIT_ALLOC_INC
#define INIT_ALLOC_INC                10
#endif

extern ulonglong opt_audit_file_size;
extern ulonglong opt_audit_ops;
extern uint opt_audit_class;
extern char *opt_audit_dir;
extern char* opt_audit_file;
extern char default_audit_dir[FN_REFLEN];
extern char default_audit_filename[FN_REFLEN];
extern DYNAMIC_ARRAY* audit_users;
extern DYNAMIC_ARRAY* audit_dbs;
extern DYNAMIC_ARRAY* audit_tables;

typedef int (*cb_init_config_vars)(char* key, char* value,char* group);
extern char* prepare_general_ops(struct mysql_event_general *, char*  );
extern char* prepare_connect_ops(struct mysql_event_connection *, char* );
extern char* databases_to_string(MYSQL_THD, char*);
extern char*  erase_password(MYSQL_THD, char* ,const char* );
extern my_bool check_users(MYSQL_THD);
extern my_bool check_databases(MYSQL_THD);
extern my_bool check_tables(MYSQL_THD);
#endif //_AUDIT_H


