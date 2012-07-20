CREATE TABLE mysql.audit (
  `audit_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `command` varchar(20) NOT NULL DEFAULT 'NULL',
  `status` int(11) NOT NULL DEFAULT '0',
  `thread_id` bigint(32) unsigned NOT NULL DEFAULT '0',
  `user` varchar(20) NOT NULL DEFAULT 'NULL',
  `external_user` varchar(20) NOT NULL DEFAULT 'NULL',
  `proxy_user` varchar(20) NOT NULL DEFAULT 'NULL',
  `host` varchar(20) NOT NULL DEFAULT 'NULL',
  `ip` varchar(20) NOT NULL DEFAULT 'NULL',
  `query` varchar(255) NOT NULL DEFAULT 'NULL',
  `charset` varchar(20) NOT NULL DEFAULT 'NULL',
  `event_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `rows` bigint(32) NOT NULL DEFAULT '0'
) ENGINE=CSV DEFAULT CHARSET=utf8 ;