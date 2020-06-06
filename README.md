# Python Domeneshop DynDns script
domeneshop dyndns update script compatible for VyOS 1.2
This is based upon https://github.com/domeneshop/python-domeneshop but modified to run under VyOS 1.2 and python3.4.2

## Install
put domeneshop-dyndns.py under /config/scripts and make it excecutable
```
chmod + x /config/scripts/domeneshop-dyndns.py
```

## VyOS config
```
set system task-scheduler task dyndnsdomeneshop executable arguments '-t <TOKEN>  -s <SECRET> -d <DOMAIN_NAME>'
set system task-scheduler task dyndnsdomeneshop executable path '/config/scripts/domeneshop-dynddns.py'
set system task-scheduler task dyndnsdomeneshop interval '15m'
```