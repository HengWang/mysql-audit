#ifndef _COMMON_H
#define _COMMON_H

/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <time.h>
#include <my_sys.h>

#define DATE_LEN  64

#ifdef __cplusplus  
extern "C" {  
#endif 

#if !defined(__WIN__)
#include <ctype.h>
  extern char *strupr(char *s);
#endif
  extern char* get_current_date(char *);
  extern char* get_current_datetime(char *);
  extern char* convert_longlong_to_datetime(longlong, char *);
#ifdef __cplusplus  
}
#endif

#endif



