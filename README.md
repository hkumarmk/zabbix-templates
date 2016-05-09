# Zabbix Templates

Collection of zabbix templates, and scripts/external-scripts.

## Memcached
  Memcached zabbix templates available use external-script to connect to memcached
remotely and check various stats.

In my case, memcache is listen only on local host, so connecting from zabbix server
was not an option, so ended up adding memcached stats using zabbix agent.

your zabbix agent need to be configured with userparameters configuration provided.
