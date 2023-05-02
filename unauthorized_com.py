import argparse
import threading
import socket
from ftplib import FTP
from dic import *
from config import *
import requests
from kazoo.client import KazooClient
from pyfiglet import Figlet


def check_ip(ip, services):
    result = {}
    result['ip'] = ip
    if not services or 'zookeeper' in services:
        result['zookeeper'] = check_zookeeper(ip)
    if not services or 'ftp' in services:
        result['ftp'] = check_ftp(ip)
    if not services or 'wordpress' in services:
        result['wordpress'] = check_wordpress(ip)
    if not services or 'kibana' in services:
        result['kibana'] = check_kibana(ip)
    if not services or 'thinkadminv6' in services:
        result['thinkadminv6'] = check_thinkadmin_v6(ip)
    if not services or 'apachespark' in services:
        result['apachespark'] = check_apache_spark(ip)
    if not services or 'kubernetes' in services:
        result['kubernetes'] = check_kubernetes_api_server(ip)
    if not services or 'btphpmyadmin' in services:
        result['btphpmyadmin'] = check_bt_phpmyadmin(ip)
    if not services or 'actuator' in services:
        result['actuator'] = check_spring_boot_actuator(ip)
    if not services or 'docker' in services:
        result['docker'] = check_docker(ip)
    if not services or 'zabbix' in services:
        result['zabbix'] = check_zabbix(ip)
    if not services or 'dubbo' in services:
        result['dubbo'] = check_dubbo(ip)
    if not services or 'dockerregistry' in services:
        result['dockerregistry'] = check_docker_registry(ip)
    if not services or 'ipc' in services:
        result['ipc'] = check_ipc(ip)
    if not services or 'redis' in services:
        result['redis'] = check_redis(ip)
    if not services or 'jenkins' in services:
        result['jenkins'] = check_jenkins(ip)
    if not services or 'druid' in services:
        result['druid'] = check_druid(ip)

    if not services or 'couchdb' in services:
        result['couchdb'] = check_couchdb(ip)
    if not services or 'uwsgi' in services:
        result['uwsgi'] = check_uwsgi(ip)
    if not services or 'hadoopyarn' in services:
        result['hadoopyarn'] = check_hadoop_yarn(ip)
    if not services or 'harbor' in services:
        result['harbor'] = check_harbor(ip)
    if not services or 'swaggerui' in services:
        result['swaggerui'] = check_swaggerui(ip)
    if not services or 'activemq' in services:
        result['activemq'] = check_activemq(ip)

    if not services or 'jupyter' in services:
        result['jupyter'] = check_jupyter_notebook(ip)
    if not services or 'phpfpm' in services:
        result['phpfpm'] = check_php_fpm_fastcgi(ip)
    if not services or 'rabbitmq' in services:
        result['rabbitmq'] = check_rabbitmq(ip)
    if not services or 'atlassian' in services:
        result['atlassian'] = check_atlassian_crowd(ip)
    if not services or 'ldap' in services:
        result['ldap'] = check_ldap(ip)
    if not services or 'weblogic' in services:
        result['weblogic'] = check_weblogic(ip)
    if not services or 'nfs' in services:
        result['nfs'] = check_nfs(ip)
    if not services or 'vnc' in services:
        result['vnc'] = check_vnc(ip)
    if not services or 'solr' in services:
        result['solr'] = check_solr(ip)
    if not services or 'jboss' in services:
        result['jboss'] = check_jboss(ip)
    if not services or 'kong' in services:
        result['kong'] = check_kong(ip)
    if not services or 'rsync' in services:
        result['rsync'] = check_rsync(ip)
    if not services or 'mongodb' in services:
        result['mongodb'] = check_mongodb(ip)
    if not services or 'memcached' in services:
        result['memcached'] = check_memcached(ip)

    if not services or 'elasticsearch' in services:
        result['elasticsearch'] = check_elasticsearch(ip)
    return result


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', help='单个IP地址进行检测')
    group.add_argument('-f', '--file', help='包含IP地址的文件进行检测')
    parser.add_argument('-s', '--service', choices=choices, help='指定要检测的服务')
    parser.add_argument('-a', '--all', action='store_true', help='测试所有支持的服务')
    parser.add_argument('-t', '--threads', type=int, default=10, help='指定线程数')
    parser.add_argument('-o', '--output', help='指定输出文件路径')
    args = parser.parse_args()

    services = []
    if args.service:
        services.append(args.service)
    elif args.all:
        services = None

    results = []

    def worker(ip):
        result = check_ip(ip, services)
        results.append(result)

    if args.ip:
        print('\n[*]已加载{0}条检测函数\n'.format(len(choices)))
        print('\n[*] starting {0}\n'.format(get_time()))
        worker(args.ip)
    else:
        with open(args.file, 'r') as f:
            ips = f.read().splitlines()

        threads = []
        print('\n[*]已加载{0}条检测函数\n'.format(len(choices)))
        print('\n[*] starting {0}\n'.format(get_time()))
        for ip in ips:
            t = threading.Thread(target=worker, args=(ip,))
            threads.append(t)
            t.start()
            if len(threads) >= args.threads:
                for t in threads:
                    t.join()
                threads.clear()

        for t in threads:
            t.join()

    if args.output:
        print('\n[+] ending {0}\n'.format(get_time()))
        with open(args.output, 'w') as f:
            for result in results:
                f.write(str(result) + '\n')
    else:
        print('\n[+] ending {0}\n'.format(get_time()))
        for result in results:
            print(result)


if __name__ == '__main__':
    banner()
    main()
