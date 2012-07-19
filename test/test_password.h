/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <my_sys.h>
#include <mysql.h>

extern my_bool check_password_insert_mysql_user_with_col(uint ,MYSQL*);
extern my_bool check_password_insert_user_with_col(uint ,MYSQL*);
extern my_bool check_password_insert_mysql_user_without_col(uint ,MYSQL*);
extern my_bool check_password_insert_user_without_col(uint ,MYSQL*);
extern my_bool check_password_update_mysql_user(uint , MYSQL*);
extern my_bool check_password_update_user(uint , MYSQL*);
extern my_bool check_password_set(uint , MYSQL*);
extern my_bool check_password_grant(uint , MYSQL*);
