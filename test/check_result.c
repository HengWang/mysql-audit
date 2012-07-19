/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <my_global.h>
#include <my_sys.h>
#include <audit.h>
#include <common.h>
#include "db_util.h"

#define READ_FLAG "r"

/*
Get the last line of audit file.

SYNOPSIS
get_last_line()
audit_file          The audit file name.
buffer               The last line content.

RETURN VALUE
0                    Failed
1                    Success 
*/
static int get_last_line(char* audit_file,char* buffer)
{
  FILE *fp = NULL;
  char ch;
  int i = 0,len=0,flag=0;

  if(!(fp = fopen(audit_file,READ_FLAG))){
    fprintf(stderr,"Couldn't open the audit file: %s !\n",audit_file);
    goto err;
  }  

  if (fseek(fp,0L,SEEK_END))
  {
    fprintf(stderr,"Couldn't seek the audit file: %s  to the end!\n",audit_file);
    goto err;
  }
  for(;;)
  {
    if (i >BUF_LEN)
      goto err;
    if((ch=fgetc(fp))!= '\n ') 
    { 
      buffer[i++]=ch; 
      fseek(fp,   -2L,   SEEK_CUR); 
    } 
    else 
    { 
      buffer[i]= '\0 '; 
      flag = 1;
      break; 
    }     
  }
  len = strlen(buffer) -1;
  for (i=0;i < len/2; i++)
  {
    char tmp = *(buffer+i);
    *(buffer+i) = *(buffer+len-i);
    *(buffer +len-i) = tmp;
  }
err:
  fclose(fp); 
  return flag;
}

/*
Get the lines of audit file from datetime to the end.

SYNOPSIS
get_lines_from_datetime()
audit_file          The audit file name.
datetime           The start datetime.
buf_array         The result of  contents.

RETURN VALUE
The lines of contents from datetime to the end.
*/
static int get_lines_from_datetime(char * audit_file,char* datetime, DYNAMIC_ARRAY* buf_array)
{
  char buffer[BUF_LEN]={0};
  char audit_time[DATE_LEN]={0};
  char* ptr;
  while(!get_last_line(audit_file,buffer))
  {
    ptr = buffer;
    for (;*ptr =='[' || *ptr==' '; ptr++);
    if(strncasecmp(ptr,datetime,strlen(datetime))<0)
      insert_dynamic(buf_array,buffer);
    else
      break;
  }
  return buf_array->elements;
}

/*
check the keywords whether in the audit file or not .

SYNOPSIS
check_file_result()
audit_file          The audit file name.
datetime           The start datetime.
key                  The keyword to check.
...                     The keywords.

RETURN VALUE
TRUE             The result in the file.  
FALSE            The result not in the file.
*/
my_bool check_file_result(char* audit_file, char* datetime, char* key,...)
{
  char buffer[BUF_LEN]={0};
  DYNAMIC_ARRAY* buf_array=NULL;
  uint idx=0;
  my_bool flag=TRUE;
  char* arg = key;
  va_list args;
  va_start(args,key);

  if (datetime)
  {
    if(buf_array = (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY), MYF(MY_WME)))
    {
      if(init_dynamic_array(buf_array,FN_LEN,INIT_ALLOC_NUM,INIT_ALLOC_INC))
      {
        fprintf(stderr,"Initialized the dynamic array of users failed.\n");
        return FALSE;
      }
    }
    if (!get_lines_from_datetime(audit_file,datetime,buf_array))
    {
      fprintf(stderr,"Couldn't get the lines from the datatime:%s of audit file: %s !\n",datetime,audit_file);
      return FALSE;
    }
  }
  else
  {
    if(!get_last_line(audit_file,buffer))
    {
      fprintf(stderr,"Couldn't get the last line of audit file: %s !\n",audit_file);
      return FALSE;
    }   
  }

  do{
    flag = TRUE;
    if (!strlen(buffer))
    {
      get_dynamic(buf_array,(uchar*)buffer,idx);
    }
    if(!strstr(buffer,arg))
    {
      flag=FALSE;
      continue;
    }
    while (arg)
    {
      arg = va_arg(args, char*);
      if(!strstr(buffer,arg))
      {
        flag = FALSE;
        continue;
      }
    }
    if(flag)
      break;
  } while(++idx < buf_array->elements);

  return flag;
}

my_bool check_table_result(char* audit_table, char* datetime, char* key,char* value,...)
{
  MYSQL* mysql;
  MYSQL_RES* res;
  MYSQL_ROW row ;  
  char buffer[BUF_LEN]={0};
  char *name,*name_value;
  uint len = 0;
  my_bool flag = TRUE;
  va_list args;
  va_start(args,value);
  my_snprintf(buffer,"SELECT COUNT(1) FROM %s WHERE AUDIT_TIME < %s and %s = %s",audit_table,datetime,key,value); 
  do{
    if((len = strlen(buffer))>BUF_LEN)
      return FALSE;
    name = va_arg(args, char*);
    name_value = va_arg(args, char*);
    if(name && name_value)
    {
      my_snprintf(buffer+len,"and %s = %s",name,name_value);
    }
  }while (name_value);

  open_connection(mysql, "localhost","audit","","mysql",3306,NULL,0);
  res = execute_query(mysql,buffer);
  row = mysql_fetch_row(res);
  if(!row[0] || atoi(row[0]))
    flag =  FALSE;
  if(res)
    mysql_free_result(res);
  close_connection(mysql);

  return flag;
}


