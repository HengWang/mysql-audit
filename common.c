/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <m_string.h>
#include "common.h"
#include "audit.h"

#if !defined(__WIN__)

/*In linux, the strupr function is not defined.*/
char *strupr(char *s)
{
  unsigned char *ucs = (unsigned char *) s;
  for ( ; *ucs != '\0'; ucs++)
  {
    *ucs = toupper(*ucs);
  }
  return s;
}
#endif

/*
Get the current date.

SYNOPSIS
get_current_date()
currentdate             The current date. 
*/
char* get_current_date(char *currentdate){
  time_t t;   
  time( &t);
  strftime(currentdate,DATE_LEN , "%Y-%m-%d", localtime(&t));
  return currentdate;
}

/*
Get the current datetime.

SYNOPSIS
get_current_datetime()
current_datetime             The current dateime. 
*/
char* get_current_datetime(char* current_datetime){
  time_t t;
  time(&t);
  strftime(current_datetime,DATE_LEN,"%Y-%m-%d %H:%M:%S",localtime(&t));
  return current_datetime;
}

/*
Convert the long long value to time string.

SYNOPSIS
convert_longlong_to_datetime()
current_datetime             The current dateime. 
*/
char* convert_longlong_to_datetime(longlong value, char* datetime){
  time_t t;
  t = (time_t)value;
  strftime(datetime,DATE_LEN,"%Y-%m-%d %H:%M:%S",localtime(&t));
  return datetime;
}


