#ifndef _AUDIT_FILE_H
#define _AUDIT_FILE_H

/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/
#include <mysql/plugin.h>
#include <audit.h>
#include <common.h>

extern char audit_file_name[FILE_NAME_LEN];
extern int audit_file_notify(MYSQL_THD ,  unsigned int , const void *);
extern int deinit_audit_file();
extern int init_audit_file();
#endif


