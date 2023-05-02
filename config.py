import random, time, os, sys

from pyfiglet import Figlet

choices=['zookeeper', 'ftp','elasticsearch','ldap','weblogic','vnc','hadoopyarn','rsync','kibana',
         'docker','dockerregistry','couchdb','jboss','jenkins','activemq','nfs','mongodb','zabbix','druid',
         'dubbo','swaggerui','harbor','ipc','actuator','btphpmyadmin','wordpress','uwsgi','kong','thinkadminv6',
         'phpfpm','solr','jupyter','kubernetes','redis','apachespark','memcached','atlassian','rabbitmq']

def banner():
    print('命令行版未授权漏洞检测')
    print('version:1.0 | made by xkllz | date:2023/05/02')
    print('**********************************************************************')
    print('----------------------------------------------------------------------')
    f = Figlet(font='slant',width=400)
    print(f.renderText('unauthorized'))
    print('----------------------------------------------------------------------')
    print('**********************************************************************')

def get_time():
    return time.strftime("@ %Y-%m-%d /%H:%M:%S/", time.localtime())


import random

# 打开 useragents.txt 文件并读取所有行
with open('user-agents.txt', 'r') as f:
    useragents = f.readlines()

# 随机选择一个 user agent
random_useragent = random.choice(useragents).strip()

headers={
    'user-agent':random_useragent
}
