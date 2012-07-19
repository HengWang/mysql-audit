/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#if !defined(__WIN__)
#include <my_dir.h>
#endif
#include <m_string.h>
#include "audit.h"
#include "audit_config.h"

#define READ_FLAG "r"

/*
Get the end pointer.

SYNOPSIS
my_strend()
str     The string to get the end pointer.

RETURN VALUE
return a character pointer to the NUL which ends s.
*/
static char* my_strend(char* str)
{
  while (*str++);
  return --str;
}

/*
Remove the comment end the option value.

SYNOPSIS
remove_end_comment()
ptr     The pointer of string to remove comment .

RETURN VALUE
return the pointer of string removed comment.
*/
static char *remove_end_comment(char *ptr)
{
  char quote= 0;  /* we are inside quote marks */
  char escape= 0; /* symbol is protected by escape chagacter */

  for (; *ptr; ptr++)
  {
    if ((*ptr == '\'' || *ptr == '\"') && !escape)
    {
      if (!quote)
        quote= *ptr;
      else if (quote == *ptr)
        quote= 0;
    }
    /* We are not inside a string */
    if (!quote && *ptr == '#')
    {
      *ptr= 0;
      return ptr;
    }
    escape= (quote && *ptr == '\\' && !escape);
  }
  return ptr;
}

/*
Parse the configure file.

SYNOPSIS
parse_config_file()
conf_file                Configure file
init_handler            Callback function for initializing the variables.

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/
int parse_config_file(const char *conf_file, cb_init_config_vars init_handler)
{
  FILE* fp = NULL;
  ulong line = 0;
  char* value,* ptr,*end;
  my_bool found_group = 0;
  char buff[BUF_LEN] = {0};
  char curr_gr[BUF_LEN] = {0};
  char key[FN_LEN] = {0};
  char key_value[FN_LEN]={0};
  DBUG_ENTER("parse_config_file");
#if !defined(__WIN__)
  {
    MY_STAT stat_info;
    if (!my_stat(conf_file,&stat_info,MYF(0)))
      DBUG_RETURN(1) ;
    if ((stat_info.st_mode & S_IWOTH) &&
      (stat_info.st_mode & S_IFMT) == S_IFREG)
    {
      DBUG_PRINT("error", ("Warning: World-writable config file '%s' is ignored\n",
        conf_file));
      DBUG_RETURN(1);
    }
  }
#endif
  if (!(fp= fopen(conf_file, READ_FLAG)))
    DBUG_RETURN(1);         /* Ignore wrong files */

  while (fgets(buff, sizeof(buff) - 1, fp))
  {
    line++;
    /* Ignore comment and empty lines */
    for (ptr= buff; my_isspace(&my_charset_latin1, *ptr); ptr++)
    {}

    if (*ptr == '#' || *ptr == ';' || !*ptr)
      continue;
    /* The current option is a group name. */
    if (*ptr == '[')        /* Group conf_file */
    {
      found_group=1;
      if (!(end=(char *) strchr(++ptr,']')))
      {
        DBUG_PRINT("error",("error: Wrong group definition in config file: %s at line %lu\n",
          conf_file,line));
        goto err;
      }
      /* Remove end space */
      for ( ; my_isspace(&my_charset_latin1,end[-1]) ; end--) ;
      end[0]=0;

      strmake(curr_gr, ptr, min((size_t) (end-ptr)+1, sizeof(curr_gr)-1));      

	   /*Callback the init_handler to process the group options. */
      if(init_handler(curr_gr,NULL,curr_gr))
      {
        found_group = 0;
        continue;
      }
	   continue;
    }
   
    if (!found_group)
    {
      DBUG_PRINT("warning",("warning: Found option without preceding group in config file: %s at line: %lu\n",
        conf_file,line));
      continue;
    }
    /* Remove the end comment. */
    end= remove_end_comment(ptr);
    if ((value= strchr(ptr, '=')))
      end= value;       /* Option without argument */

    for ( ; my_isspace(&my_charset_latin1,end[-1]) ; end--) ;
    strmake(key,ptr,end-ptr);

    if (!value)
    {
      DBUG_PRINT("error",("error: Found option without value in config file: %s at line: %lu\n",
        conf_file,line));
      goto err;
    }
    else
    {
      /* Remove pre- and end space */
      char *value_end;
      for (value++ ; my_isspace(&my_charset_latin1,*value); value++) ;
      value_end=my_strend(value);
      /*
      We don't have to test for value_end >= value as we know there is
      an '=' before
      */
      for ( ; my_isspace(&my_charset_latin1,value_end[-1]) ; value_end--) ;
      if (value_end < value)      /* Empty string */
        value_end=value;

      /* remove quotes around argument */
      if ((*value == '\"' || *value == '\'') && /* First char is quote */
        (value + 1 < value_end ) && /* String is longer than 1 */
        *value == value_end[-1] ) /* First char is equal to last char */
      {
        value++;
        value_end--;
      }
      ptr = key_value;
      for ( ; value != value_end; value++)
      {
        if (*value == '\\' && value != value_end-1)
        {
          switch(*++value) {
    case 'n':
      *ptr++='\n';
      break;
    case 't':
      *ptr++= '\t';
      break;
    case 'r':
      *ptr++ = '\r';
      break;
    case 'b':
      *ptr++ = '\b';
      break;
    case 's':
      *ptr++= ' ';      /* space */
      break;
    case '\"':
      *ptr++= '\"';
      break;
    case '\'':
      *ptr++= '\'';
      break;
    case '\\':
      *ptr++= '\\';
      break;
    default:        /* Unknown; Keep '\' */
      *ptr++= '\\';
      *ptr++= *value;
      break;
          }
        }
        else
          *ptr++= *value;
      }
      *ptr=0;
      /*Callback the init_handler to process the variable options. */
      if(init_handler(key,key_value,curr_gr)){
        DBUG_PRINT("warning",("warning: The option is invalid in config file: %s at line: %lu\n",
          conf_file,line));
        continue;
      }
    }
  }
  my_fclose(fp, MYF(0));
  DBUG_RETURN(0);

err:
  my_fclose(fp, MYF(0));
  DBUG_RETURN(-1);         /* Fatal error */
}
