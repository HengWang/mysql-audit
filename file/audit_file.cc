/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <sql/sql_class.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <audit.h>
#include <common.h>

#define CREATE_FLAG  0700
#define APPEND_FLAG  "a+"

/* Variables definition*/
static FILE* audit_fp = NULL;
static char audit_file_dir[FILE_DIR_LEN] ={0};
char audit_file_name[FILE_NAME_LEN] ={0};
static char audit_date[DATE_LEN]={0};

static int file_id = 0;

/*
Build the audit file name by the directory, current date, given filename and file size.
If the file size is not 0, make the audit subdirectory of current date, and the files in
the subdirectory is incrementing by file id, which is a static incremental value.

SYNOPSIS
audit_general()
event          The object of struct mysql_event_general
op_str        The general operation string type

DESCRIPTION
If the current operation is general, audit the operation. 
*/
static char* make_audit_file_name(char* dir,char* date, char* filename,ulonglong file_size)
{
  DBUG_ENTER("make_audit_file_name"); 
  if(file_size)
  {
    strxnmov(audit_file_dir,FILE_DIR_LEN,dir,FN_DIRSEP,date, NullS);
    snprintf(audit_file_name,2*FN_REFLEN+DATE_LEN,"%s%s%s%s%s.%06X",dir,FN_DIRSEP,date,FN_DIRSEP,filename,file_id);
  }else{
    strmake(audit_file_dir,dir,FILE_DIR_LEN);
    snprintf(audit_file_name,2*FN_REFLEN+DATE_LEN,"%s%s%s.%s",dir,FN_DIRSEP,filename,date);
  } 

  if (my_access(audit_file_dir, W_OK))
  {
    if(my_mkdir(audit_file_dir, CREATE_FLAG , MYF(0)))
    {
      DBUG_PRINT("error",("Can't create the directory of subdirectory of %s,"
        "check the directory %s whether be writable",audit_file_dir,dir));
      DBUG_RETURN(NullS);
    }
  }
  DBUG_RETURN( audit_file_name);
}

/*
Audit the general operations into file.

SYNOPSIS
audit_general()
event          The object of struct mysql_event_general
op_str        The general operation string type

DESCRIPTION
If the current operation is general, audit the operation. 
*/
static void audit_general(MYSQL_THD thd,mysql_event_general* event,char* op_str)
{
  char* query;
  char audit_datetime[DATE_LEN] = {0};
  char execute_datetime[DATE_LEN] = {0};
  char dbs_buf[BUF_LEN] = {0};
  DBUG_ENTER("audit_general");    
  fprintf(audit_fp,"[%s] [%s] error_code:[%d] # thread_id:[%lu] # user:[%s] # databases:[%s] # query:[%s] # charset:[%s] # event_time:[%s] # rows:[%lu]\n",
    get_current_datetime(audit_datetime),
    op_str? op_str: event->general_command,
    event->general_error_code? event->general_error_code:0,
    event->general_thread_id? event->general_thread_id:(unsigned long)0,
    event->general_user? event->general_user:(thd->main_security_ctx.user? thd->main_security_ctx.user:"NULL"),
    databases_to_string(thd,dbs_buf),
    (query = erase_password(thd,op_str,event->general_query)),
    event->general_charset? event->general_charset->name:"NULL",
    convert_longlong_to_datetime(event->general_time? event->general_time:(unsigned long long)0,execute_datetime),
    event->general_rows? event->general_rows:(unsigned long long)0);    
  fflush(audit_fp);
  free(query);
  DBUG_VOID_RETURN;
}


/*
Audit the connect operations into file.

SYNOPSIS
audit_connects()
event          The object of struct mysql_event_connection
op_str        The general operation string type

DESCRIPTION
If the current operation is connection, audit the operation 
*/
static void audit_connect(MYSQL_THD thd,mysql_event_connection* event, char* op_str)
{
  char audit_datetime[DATE_LEN] = {0};
  DBUG_ENTER("audit_connect");  
  fprintf(audit_fp,"[%s] [%s] status:[%d] # thread_id:[%lu] # user:[%s] # external-user:[%s] # proxy-user:[%s] # host:[%s] # ip:[%s] # database:[%s]\n",
    get_current_datetime(audit_datetime),
    op_str,   
    event->status? event->status:0,
    event->thread_id? event->thread_id : (unsigned long)0,
    event->user? event->user:(thd->main_security_ctx.user? thd->main_security_ctx.user:"NULL"),
    event->external_user? event->external_user:"NULL",
    event->proxy_user? event->proxy_user:"NULL",
    event->host? event->host:"NULL",
    event->ip? event->ip:"NULL",
    event->database? event->database:"NULL");     
  fflush(audit_fp);
  DBUG_VOID_RETURN;
}

/*
Initialized the file handler for auditting.

SYNOPSIS
init_audit_file()

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/
int init_audit_file()
{
  MY_STAT stat_info;
  char* filename;
  DBUG_ENTER("init_audit_file");  
  /* Initialize the audit file.*/
  do{
    filename = make_audit_file_name(opt_audit_dir,get_current_date(audit_date),opt_audit_file,opt_audit_file_size);
    if (!my_stat(filename,&stat_info,MYF(0)))
      break;
    if (opt_audit_file_size && (ulonglong)stat_info.st_size > opt_audit_file_size)
      file_id++;
    else
      break;
  } while(1);

  /* If the audit file descriptor is NULL then open the file.*/
  if(!audit_fp)
  {
    if(!(audit_fp = fopen(filename,APPEND_FLAG))){
      DBUG_PRINT("error",("Can't open the file: %s",filename));
    }  
  }
  DBUG_RETURN(0);
}
/*
Deinitialized the file handler for auditting .

SYNOPSIS
deinit_audit_file()

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/

int deinit_audit_file()
{
  DBUG_ENTER("deinit_audit_file");  
  if(fflush(audit_fp))
    DBUG_PRINT("error",("Flush the audit information into file faild before close the file."));
  if (audit_fp)
    fclose(audit_fp);
  audit_fp=NULL;
  DBUG_RETURN(0);
}

/*
Audit the operations information into file.

SYNOPSIS
audit_file_notify()
thd                Connection context
event_class    The event class: general or connect
event             The event object.

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/
int audit_file_notify(MYSQL_THD thd ,
                      unsigned int event_class,
                      const void *event)
{
  char op_str[FN_LEN]={0};
  char current_date[DATE_LEN]={0};
  MY_STAT stat_info;
  int flag = 1;
  struct mysql_event_general *my_event_gen=NULL;
  struct mysql_event_connection *my_event_con=NULL;
  DBUG_ENTER("audit_file_notify");
  if(!opt_audit_ops || !audit_users->elements || !audit_dbs->elements || !audit_tables->elements)
  {
    DBUG_PRINT("error",("The value of opt_audit_ops is: %lu or the audit_users elements is %lu",
      opt_audit_ops,audit_users->elements));
    DBUG_RETURN(-1);
  }
  /* The current date is old, initialize the new audit file. */
  if(strncmp(get_current_date(current_date),audit_date,DATE_LEN))
  {
    file_id = 0;
    deinit_audit_file();
    init_audit_file();
  }

  if (!my_stat(audit_file_name,&stat_info,MYF(0)))
  {
    DBUG_PRINT("error",("Get the status of file: %s failed.",
      audit_file_name));
    DBUG_RETURN(-1);
  }
  /* If the current file is bigger than the given restrict size, then create a new file.*/
  if (opt_audit_file_size && (ulonglong)stat_info.st_size > opt_audit_file_size)
  { 
    file_id++;
    deinit_audit_file();
    init_audit_file();
  }

  /*The event class is general operations*/
  if (event_class == MYSQL_AUDIT_GENERAL_CLASS && audit_fp != NULL)
  {
    my_event_gen = (struct mysql_event_general *)event; 
    /*The current status is vaild. The event parameters and the user and the object must be auditted.*/
    if( my_event_gen->general_command && my_event_gen->general_command != EMPTY_KEY &&
      my_event_gen->general_query && my_event_gen->general_query != EMPTY_KEY &&
      !my_event_gen->general_error_code &&
      check_users(thd) &&
      (check_databases(thd) ||
      check_tables(thd)))
    {
      prepare_general_ops(my_event_gen,op_str);
      if (strlen(op_str)!=0)
      {
        /*Call the audit_general function to write the operation into the file*/
        audit_general(thd,my_event_gen,op_str);
        flag = 0;
      }  
    }         
  }
  /*The event class is connection*/
  else if (event_class == MYSQL_AUDIT_CONNECTION_CLASS && audit_fp != NULL)
  {
    my_event_con =  (struct mysql_event_connection *)event;
    if (!my_event_con->status)
    {
      if(!check_users(thd))
      {
        DBUG_PRINT("info",("The user:%s is invalid.",thd->main_security_ctx.user));
        DBUG_RETURN(1);
      }
      prepare_connect_ops(my_event_con,op_str);
      if (strlen(op_str)!=0)
      {
        /*Call the audit_general function to write the operation into the file*/
        audit_connect(thd,my_event_con,op_str);
        flag = 0;
      }  
    }
  } 
  DBUG_RETURN(flag);
}

