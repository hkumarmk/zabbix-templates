This template need an env file under /etc/zabbix/scripts/rabbitmq/.rab.auth pushed
to all agents in case rabbitmq is not listening on localhost.

```
$ cat /etc/zabbix/scripts/rabbitmq/.rab.auth 
HOSTNAME=10.204.217.162
NODE=10.204.217.162
```
