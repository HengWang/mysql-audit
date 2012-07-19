#ifndef _AUDIT_TABLE_H
#define _AUDIT_TABLE_H

/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <mysql/plugin.h>
#include <m_string.h>

extern LEX_STRING AUDIT_NAME;
extern LEX_STRING MYSQL_SCHEMA_NAME;
extern int audit_table_notify(MYSQL_THD ,  unsigned int , const void *);
extern int init_audit_table();
extern int deinit_audit_table();
#endif


