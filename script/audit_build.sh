#! /bin/sh

###########################################################
# Copyright (c) 2012, Henry.Wang. All rights reserved.
#
# This program is a script to build the audit plugin. 
###########################################################

set -x

# Get the key value of input arguments format like '--args=value'.
get_key_value()
{
    echo "$1" | sed 's/^--[a-zA-Z_-]*=//'     
}

# Usage will be helpful when you need to input the valid arguments.
usage()
{
cat <<EOF
Usage: $0 [configure-options]
  -?, --help                       Show this help message.
  --mysqldir=<>                    Set the mysql directory.
  --auditdir=<>                    Set the audit directory.
  --host=<>                        Set the host name.
  --port=<>                        Set the port number.
  --user=<>                        Set the user name.
  --password=<>                    Set the password of user.
  --socket=<>                      Set the socket file for unix/linux.
  --version=<>                     Set the version of mysql server.
                                   Only [5.5.15] release,[5.5.20] release
                   and debug version has been tested.
  --type=<>                        Set the type of MySQL server.
                                   [release] or [debug]
  -i,--install                     Install the audit plugin .
  -u,--uninstall                   Uninstall the audit plugin.
  -c,--cleanup                     Cleanup the audit plugin.  
Note: this script is intended for internal use by developers.

EOF
}

# Print the default value of the arguments of the script.
print_default()
{
cat <<EOF
  The default value of the variables:
  
  mysqldir          $MYSQLDIR
  auditdir          $AUDITDIR
  host              $HOST
  port              $PORT
  user              $USER
  password          $PASSWORD
  socket            $SOCKET
  version           $VERSION
  type              $TYPE
EOF
}

# Parse the input arguments and get the value of the input argument.
parse_options()
{
  while test $# -gt 0
  do
    case "$1" in    
    --mysqldir=*)
      MYSQLDIR=`get_key_value "$1"`;;
    --auditdir=*)
      AUDITDIR=`get_key_value "$1"`;;
    --host=*)
      HOST=`get_key_value "$1"`;;
    --port=*)
      PORT=`get_key_value "$1"`;;
    --user=*)
      USER=`get_key_value "$1"`;;
    --password=*)
      PASSWORD=`get_key_value "$1"`;;
    --socket=*)
      SOCKET=`get_key_value "$1"`;;
    --version=*)
      VERSION=`get_key_value "$1"`;;
    --type=*)
      TYPE=`get_key_value "$1"`;;
    -i | --install)
      INSTALL=1;;
    -u | --uninstall)
      UNINSTALL=1;;
    -c | --cleanup)
      CLEANUP=1;;    
    -? | --help)
      usage
      print_default
      exit 0;;
    *)
      echo "Unknown option '$1'"
      exit 1;;
    esac
    shift
  done
}

prepare()
{  
  echo "Prepare the audit plugin configure file and library..."
  echo "Check the mysql plugin dir:${MYSQL_PLUGIN_DIR} or create it."
  [[ -d ${MYSQL_PLUGIN_DIR} ]] || sudo mkdir ${MYSQL_PLUGIN_DIR}
  echo "Copy the config file audit.cnf to ${MYSQL_PLUGIN_DIR}."
  cp ../etc/audit.cnf ${MYSQL_PLUGIN_DIR}/audit.cnf
  
  echo "Check the mysql real plugin dir:${MYSQL_REAL_PLUGIN_DIR} or create it."
  [[ -d ${MYSQL_REAL_PLUGIN_DIR} ]] || sudo mkdir ${MYSQL_REAL_PLUGIN_DIR}  
  echo "Copy the dynamic library audit.so to ${MYSQL_REAL_PLUGIN_DIR}."
  cp ./percona-server-${VERSION}-${TYPE}/audit.so ${MYSQL_REAL_PLUGIN_DIR}/audit.so
    
  echo "Prepare the audit plugin success!"
}

prepare_audit()
{
  echo "Prepare the audit directory..."
  
  if [ ! -f ${MYSQL_PLUGIN_DIR}/audit.cnf ]
  then  
  echo "!!!Error: The audit configure file: ${MYSQL_PLUGIN_DIR}/audit.cnf is not exists!"
  exit -1
  fi
  
  if [ ! -f ${MYSQL_REAL_PLUGIN_DIR}/audit.so ]
  then
    echo "!!!Error: The audit library: ${MYSQL_REAL_PLUGIN_DIR}/audit.so is not exists!"
  exit -1
  fi
  
  echo "Create table for audit class 'TABLE' and record the operations into table."
  if [ ! -f ./audit.sql ]
  then
    echo "!!!Warning: The audit class 'TABLE' can not be used!"
  else
    $MYSQL_CLIENT -h${HOST} -P${PORT} -u${USER} -p"${PASSWORD}" -S${SOCKET} mysql < ./audit.sql
  fi
  
  echo "Modified the variable of audit_dir in configure file: ${MYSQL_PLUGIN_DIR}/audit.cnf"  
  awk -F, '{for(i=1;i<=NF;i++){if($i~"audit_dir =")$i="audit_dir=${AUDITDIR}"}print $0}' ${MYSQL_PLUGIN_DIR}/audit.cnf > ${MYSQL_PLUGIN_DIR}/audit.cnf
  
  echo "Check the audit directory: ${AUDITDIR} or create it."
  [[ -d ${AUDITDIR} ]] || sudo mkdir ${AUDITDIR}
  sudo chown -R mysql:mysql ${AUDITDIR}
}

install()
{
  echo "Install the audit plugin..."
  res=`$MYSQL_CLIENT -h${HOST} -P${PORT} -u${USER} -p"${PASSWORD}" -S${SOCKET} -e"INSTALL PLUGIN audit SONAME 'audit.so'"`
  if [ -n "$res" ]
  then
    echo "!!!Error: Install audit plugin failed!"
    echo "$res"
    exit -1
  else
    echo "Install the audit plugin success!"
  fi
}

uninstall()
{
  echo "Uninstall the audit plugin..."
  res=`$MYSQL_CLIENT -h${HOST} -P${PORT} -u${USER} -p"${PASSWORD}" -S${SOCKET} -e"UNINSTALL PLUGIN audit"`
  if [ -n "$res" ]
  then
    echo "!!!Error: Uninstall audit plugin failed!"
    echo "$res"
    exit -1
  else
    echo "Uninstall the audit plugin success!"
  fi
}

cleanup()
{
  echo "Clean up the audit plugin..."
  uninstall
  rm -rf ${MYSQL_PLUGIN_DIR}/audit.cnf
  rm -rf ${MYSQL_REAL_PLUGIN_DIR}/audit.so
  echo "Clean up the audit plugin success!"
}

############################################################
# Define the variables the script used for executing.
MYSQLDIR=/home/q/mysql
AUDITDIR=/home/q/mysql/audit
HOST=localhost
PORT=3306
USER=root
PASSWORD=
SOCKET=/tmp/mysql.sock
VERSION=5.5.20
TYPE=release
INSTALL=0
UNINSTALL=0
CLEANUP=0

# Call the parse_options function to parse the input arguments.
parse_options "$@"

if [ -d $MYSQLDIR ]
then
  MYSQL_BIN_DIR=${MYSQLDIR}/bin
  MYSQL_PLUGIN_DIR=${MYSQLDIR}/lib/plugin
  MYSQL_CLIENT=${MYSQL_BIN_DIR}/mysql
  
  if [ ! -f ${MYSQL_CLIENT} ]
  then
    echo "!!!Error: MySQL client:${MYSQL_CLIENT} is not exists! "
  exit -1
  fi
  
  MYSQL_REAL_PLUGIN_DIR=`$MYSQL_CLIENT -h${HOST} -P${PORT} -u${USER} -p"${PASSWORD}" -S${SOCKET} -e"SHOW VARIABLES LIKE 'plugin_dir'" | awk '/plugin_dir/ {print $2}'`
  echo $MYSQL_REAL_PLUGIN_DIR
  if [ -z "${MYSQL_REAL_PLUGIN_DIR}" ]
  then
    MYSQL_REAL_PLUGIN_DIR=${MYSQL_PLUGIN_DIR}
  fi
 
  prepare
    
  prepare_audit
  
  if [ $INSTALL -eq 1 ]     
  then
    install
  fi
  
  if [ $UNINSTALL -eq 1 ]
  then 
    uninstall
  fi
  
  if [ $CLEANUP -eq 1 ]
  then 
    cleanup
  fi
  
  echo "Build the audit plugin success!"  
  
else
  echo "!!!Error: The mysql base directory:${MYSQLDIR} is not exists!"
  exit -1
fi








