#ifndef _AUDIT_CONFIG_H
#define _AUDIT_CONFIG_H

/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include "audit.h"


#ifdef __cplusplus  
extern "C" {  
#endif 
  extern int parse_config_file(const char*,cb_init_config_vars);

#ifdef __cplusplus  
}
#endif
#endif


