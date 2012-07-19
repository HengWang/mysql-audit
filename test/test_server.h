/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <my_sys.h>
#include <mysql.h>

/*
extern my_bool check_sleep(uint ,MYSQL* );
extern my_bool check_init_db(uint ,MYSQL* );
*/

extern my_bool check_field_list(uint ,MYSQL* );
extern my_bool check_refresh(uint ,MYSQL* );
extern my_bool check_shutdown(uint ,MYSQL* );
/*
extern my_bool check_statistics(uint ,MYSQL* );
*/
extern my_bool check_processlist(uint ,MYSQL* );
extern my_bool check_kill(uint ,MYSQL* );
extern my_bool check_debug(uint ,MYSQL* );
extern my_bool check_ping(uint ,MYSQL* );

/*
extern my_bool check_time(uint ,MYSQL* );
extern my_bool check_delay_insert(uint ,MYSQL* );
extern my_bool check_binlog_dump(uint ,MYSQL* );
extern my_bool check_table_dump(uint ,MYSQL* );
extern my_bool check_connect_out(uint ,MYSQL* );
extern my_bool check_register_slave(uint ,MYSQL* );
extern my_bool check_prepare(uint ,MYSQL* );
extern my_bool check_execute(uint ,MYSQL* );
extern my_bool check_long_data(uint ,MYSQL* );
extern my_bool check_close_stmt(uint ,MYSQL* );
extern my_bool check_reset_stmt(uint ,MYSQL* );
*/

extern my_bool check_set_option(uint ,MYSQL* );
extern my_bool check_fetch(uint ,MYSQL* );

/*
extern my_bool check_daemon(uint ,MYSQL* );
*/

extern my_bool check_error(uint ,MYSQL* );


