/* Copyright (c) 2012, Heng.Wang. All rights reserved.

This program is aimed to audit the mysql database operations. 
If you have the more efficient method to audit the mysql database,
thanks for your sharing with the developers. It's pleasure for you
to contact me king_wangheng@163.com.  
*/

#include <sql/sql_class.h>
#include <sql/sql_base.h>   
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <audit.h>
#include <common.h>


/**
* Definition of AUDIT schema name
*/
LEX_STRING AUDIT_NAME= {C_STRING_WITH_LEN("audit")};

/* Variables definition*/
static TABLE_LIST table_list;
static TABLE *table;

/*
Audit the operations into table.

SYNOPSIS
audit_info()
thd                    The thd object.
audit_time          The audit time.
command           The command name.
status                 The status of operation execution.
thread_id            The thread id.
user                    The user of current operation.
external_user       The external user.
proxy_user          The proxy user.
host                     The host name of connected.
ip                         The ip of connected.
query                    The content of current operation.
charset                  The name of character set.
event_time             The event time of current operation.
rows                      The influence rows.

DESCRIPTION
If the current operation is general, audit the operation. 
*/
static int audit_info(MYSQL_THD thd,
                      my_time_t audit_time,
                      char* command, 
                      int status, 
                      unsigned long thread_id, 
                      char* user,
                      const char* external_user,
                      const char* proxy_user,
                      char* host, 
                      char* ip, 
                      char* dbs,
                      const char* query, 
                      const char* charset, 
                      my_time_t event_time,  
                      unsigned long long  rows)
{
  DBUG_ENTER("audit_info");  

  DBUG_ASSERT(table->field[0]->type() == MYSQL_TYPE_TIMESTAMP);
  if (audit_time)
    ((Field_timestamp*) table->field[0])->store_timestamp(audit_time);
  else
    table->field[0]->set_default();

  if (table->field[1]->store(command, strlen(command), thd->variables.character_set_client))
  {
    DBUG_RETURN(1);
  }

  if (status || table->field[2]->store(status, TRUE))
  {
    DBUG_RETURN(1);
  }

  if (table->field[3]->store(thread_id,TRUE))
  {
    DBUG_RETURN(1);
  }

  if (user)
    if(table->field[4]->store(user,strlen(user), thd->variables.character_set_client))
      DBUG_RETURN(1);
    else
      table->field[4]->set_default();

  if (external_user){
    if(table->field[5]->store(external_user,strlen(external_user),thd->variables.character_set_client))
      DBUG_RETURN(1);
  }else
    table->field[5]->set_default();

  if (proxy_user){
    if(table->field[6]->store(proxy_user,strlen(proxy_user),thd->variables.character_set_client))
      DBUG_RETURN(1);
  }else
    table->field[6]->set_default();

  if (host)
  {
    if (table->field[7]->store(thd->main_security_ctx.host,strlen(thd->main_security_ctx.host),thd->variables.character_set_client))
      DBUG_RETURN(1);
  }else
    table->field[7]->set_default();

  if (ip)
  {
    if(table->field[8]->store(ip,strlen(ip),thd->variables.character_set_client))
      DBUG_RETURN(1);
  }else
    table->field[8]->set_default();   

  if(dbs)
  {
    if(table->field[9]->store(dbs,strlen(charset),thd->variables.character_set_client))
      DBUG_RETURN(1);
  }else
    table->field[9]->set_default();

  if (query)
  {
    if (table->field[10]->store(query,strlen(query),thd->variables.character_set_client))
       DBUG_RETURN(1);
  }else
    table->field[10]->set_default();

  if(charset)
  {
    if(table->field[11]->store(charset,strlen(charset),thd->variables.character_set_client))
      DBUG_RETURN(1);
  }else
    table->field[11]->set_default();

  DBUG_ASSERT(table->field[12]->type() == MYSQL_TYPE_TIMESTAMP);
  if (event_time)
    ((Field_timestamp*) table->field[12])->store_timestamp(event_time);
  else
    table->field[12]->set_default();

  if(table->field[13]->store(rows, TRUE))
    DBUG_RETURN(1);

  table->field[0]->set_notnull();
  table->field[1]->set_notnull();
  table->field[2]->set_notnull();
  table->field[3]->set_notnull();
  table->field[4]->set_notnull();
  table->field[5]->set_notnull();
  table->field[6]->set_notnull();
  table->field[7]->set_notnull();
  table->field[8]->set_notnull();
  table->field[9]->set_notnull();
  table->field[10]->set_notnull();
  table->field[11]->set_notnull();
  table->field[12]->set_notnull();
  table->field[13]->set_notnull();

  if (table->file->ha_write_row(table->record[0]))
    DBUG_RETURN(1);

  DBUG_RETURN(0);
}

/*
Audit the general operations into table.

SYNOPSIS
audit_general()
event          The object of struct mysql_event_general
op_str        The general operation string type

DESCRIPTION
If the current operation is general, audit the operation. 
*/
static void audit_general(MYSQL_THD thd,mysql_event_general* event, char* op_str)
{
  time_t t;
  char* query;
  char dbs_buf[BUF_LEN] = {0};
  DBUG_ENTER("audit_general");  
  if(audit_info(thd,
    (my_time_t)time(&t),
    op_str,
    event->general_error_code,
    event->general_thread_id,
    thd->main_security_ctx.user,
    (const char*) 0,
    (const char*) 0,
    thd->main_security_ctx.host,
    thd->main_security_ctx.ip,
    databases_to_string(thd,dbs_buf),
    (query = erase_password(thd,op_str,event->general_query)),
    event->general_charset->name,
    (my_time_t)event->general_time,
    event->general_rows))
    DBUG_PRINT("error",("Audit the general operations failed."));
  free(query);
  DBUG_VOID_RETURN;
}
/*
Audit the connect operations into table.

SYNOPSIS
audit_connects()
event          The object of struct mysql_event_connection
op_str        The general operation string type

DESCRIPTION
If the current operation is connection, audit the operation 
*/
static void audit_connect(MYSQL_THD thd,mysql_event_connection* event, char* op_str)
{
  time_t t;
  DBUG_ENTER("audit_connect");  
  if(audit_info(thd,
    (my_time_t)time(&t),
    op_str,
    event->status,
    event->thread_id,
    thd->main_security_ctx.user,
    event->external_user,
    event->proxy_user,
    thd->main_security_ctx.host,
    thd->main_security_ctx.ip,
    (char*)0,
    (const char*)0,
    (const char*)0,
    (my_time_t)time(&t),
    (unsigned long long)0))
    DBUG_PRINT("error",("Audit the connect operations failed."));
  DBUG_VOID_RETURN;
}

/*
Initialize the plugin at server start or plugin installation.

SYNOPSIS
init_audit_table()

DESCRIPTION
Initialized the table for auditting and the 
commands number of localhost

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/
int init_audit_table()
{
  DBUG_ENTER("init_audit_table"); 
  DBUG_RETURN(0);
}
/*
Deinitialized the table for auditting .

SYNOPSIS
deinit_audit_table()

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/

int deinit_audit_table()
{
  DBUG_ENTER("deinit_audit_table"); 
  DBUG_RETURN(0);
}

/*
Audit the operations information into table.

SYNOPSIS
audit_table_notify()
thd                Connection context
event_class    The event class: general or connect
event             The event object.

RETURN VALUE
0                    success
1                    failure (cannot happen)
*/
int audit_table_notify(MYSQL_THD thd ,
                       unsigned int event_class,
                       const void *event)
{
  char op_str[FN_LEN]={0};
  struct mysql_event_general *my_event_gen=NULL;
  struct mysql_event_connection *my_event_con=NULL;
  my_bool save_time_zone_used=FALSE;
  my_bool need_close=FALSE;
  my_bool need_rnd_end=FALSE;
  Open_tables_backup open_tables_backup;
  ulonglong save_thd_options;
  int flag = 1;

  uint flags= ( MYSQL_OPEN_IGNORE_GLOBAL_READ_LOCK |
    MYSQL_LOCK_IGNORE_GLOBAL_READ_ONLY |
    MYSQL_OPEN_IGNORE_FLUSH |
    MYSQL_LOCK_IGNORE_TIMEOUT |
    MYSQL_LOCK_LOG_TABLE);

  DBUG_ENTER("audit_table_notify");
  save_time_zone_used= thd->time_zone_used;

  save_thd_options= thd->variables.option_bits;
  thd->variables.option_bits&= ~OPTION_BIN_LOG;
  table_list.init_one_table(MYSQL_SCHEMA_NAME.str, MYSQL_SCHEMA_NAME.length,
    AUDIT_NAME.str , AUDIT_NAME.length, AUDIT_NAME.str, TL_WRITE_CONCURRENT_INSERT); 

  /* Save value that is changed in mysql_lock_tables() */
  ulonglong save_utime_after_lock= thd->utime_after_lock;

  thd->reset_n_backup_open_tables_state(&open_tables_backup);

  if ((table= open_ltable(thd, &table_list, table_list.lock_type, flags)))
  {
    /* Make sure all columns get assigned to a default value */
    table->use_all_columns();
    table->no_replicate= 1;
    /*
    Don't set automatic timestamps as we may want to use time of logging,
    not from query start
    */
    table->timestamp_field_type= TIMESTAMP_NO_AUTO_SET;
  }
  else
    thd->restore_backup_open_tables_state(&open_tables_backup);

  thd->utime_after_lock= save_utime_after_lock;

  if (!table)
  {
    flag = -1;
    goto err;
  }
  need_close= TRUE;

  if (table->file->extra(HA_EXTRA_MARK_AS_LOG_TABLE) ||
    table->file->ha_rnd_init(0))
  {
    flag = -1;
    goto err;
  }

  need_rnd_end= TRUE;

  /* Honor next number columns if present */
  table->next_number_field= table->found_next_number_field;
  /* check that all columns exist */
  if (table->s->fields < 13)
  {
    flag = -1;
    goto err;
  }

  if (event_class == MYSQL_AUDIT_GENERAL_CLASS)
  {
    my_event_gen = (struct mysql_event_general *)event; 
    /*The current status is vaild. The event parameters and the user and the object must be auditted.*/
    if( my_event_gen->general_command && my_event_gen->general_command != EMPTY_KEY &&
      my_event_gen->general_query && my_event_gen->general_query != EMPTY_KEY &&
      !my_event_gen->general_error_code && check_users(thd) && check_objects(thd) )
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
  else if (event_class == MYSQL_AUDIT_CONNECTION_CLASS)
  {
    my_event_con =  (struct mysql_event_connection *)event;
    if (!my_event_con->status)
    {
      if(!check_users(thd))
      {
        DBUG_PRINT("info",("The user:%s is invalid.",thd->main_security_ctx.user));
        flag = -1;
        goto err;
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
err:
  if (need_rnd_end)
  {
    table->file->ha_rnd_end();
    table->file->ha_release_auto_increment();
  }
  if (need_close)
  {
    close_thread_tables(thd);
    thd->restore_backup_open_tables_state(&open_tables_backup);
  }
  thd->variables.option_bits= save_thd_options;
  thd->time_zone_used= save_time_zone_used;
  DBUG_RETURN(flag);
}



