import ftplib
import json
import socket
import redis
import ldap3

from config import *
import memcache as memcache
import pymongo as pymongo
import requests

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

def check_elasticsearch(ip):
    endpoints = [
        f'http://{ip}:9200/_cat',
        f'http://{ip}:9200/_nodes',
        f'http://{ip}:9200/_cluster/health'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return f"{ip}[+]*****存在elasticsearch未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist elasticsearch未授权访问漏洞"


def check_jboss(ip):
    endpoints = [
        f'http://{ip}:8080/jmx-console/',
        f'http://{ip}:8080/console/',
        f'http://{ip}:8080/invoker/JMXInvokerServlet'
    ]
    for url in endpoints:
        try:
            jboss_response = requests.get(url, headers=headers)
            if 'jboss' in jboss_response.headers.get('Server', '') and 'Welcome to JBossAS' in jboss_response.text:
                return f"{ip}[+]*****存在jboss未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist jboss未授权访问漏洞"


def check_ldap(ip):
    try:
        server = ldap3.Server(f'ldap://{ip}:389')
        conn = ldap3.Connection(server)
        if conn.bind():
            return f"{ip}[+]*****存在ldap未授权访问漏洞"
        else:
            return f"{ip}not exist ldap未授权访问漏洞"
        conn.unbind()
    except:
        return "无法连接到 ldap 服务"


def check_redis(ip):
    redis_port = 6379
    try:
        r = redis.Redis(host=ip, port=redis_port, socket_timeout=3)
        info = r.info()
        return f"{ip}[+]*****存在redis未授权访问漏洞"
    except redis.exceptions.AuthenticationError:
        return f"{ip}not exist redis未授权访问漏洞"
    except redis.exceptions.ConnectionError:
        return f"{ip}not exist redis未授权访问漏洞"
    except Exception:
        return f"{ip}not exist redis未授权访问漏洞"


def check_nfs(ip):
    try:
        nfs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        nfs_socket.settimeout(3)
        nfs_socket.connect((ip, 2049))
        nfs_socket.sendall(
            b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        response = nfs_socket.recv(1024)
        if b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x02\x00\x00\x00\x01' in response:
            return f"{ip}[+]*****存在nfs未授权访问漏洞"
        else:
            return f"{ip}not exist nfs未授权访问漏洞"
    except:
        return "无法连接到该 IP"


def check_ftp(ip):
    try:
        ftp = ftplib.FTP(ip)
        ftp.login()
        ftp.cwd('/')
        ftp.quit()
        return f"{ip}[+]*****存在ftp未授权访问漏洞"
    except:
        # 尝试常见弱密码
        weak_passwords = [('admin', 'admin'), ('anonymous', 'anonymous')]
        for user, pwd in weak_passwords:
            try:
                ftp = ftplib.FTP(ip)
                ftp.login(user, pwd)
                ftp.cwd('/')
                ftp.quit()
                return f"{ip}[+]*****存在ftp未授权访问漏洞（弱密码）"
            except:
                continue
        return f"{ip}not exist ftp未授权访问漏洞"


def check_zookeeper(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 2181))
        sock.send(b'stat')
        data = sock.recv(1024)
        if data:
            return f"{ip}[+]*****存在zookeeper未授权访问漏洞"
        else:
            return f"{ip}not exist zookeeper未授权访问漏洞"
        sock.close()
    except:
        return "无法连接到 Zookeeper 服务"


def check_vnc(ip):
    try:
        import pyvnc  # 使用pyvnc库进行VNC连接尝试，需先安装该库
        client = pyvnc.VNC(ip, 5900)  # 假设默认端口5900，可根据实际调整
        client.connect()
        return f"{ip}[+]*****存在vnc未授权访问漏洞"
        client.disconnect()
    except:
        return f"{ip}not exist vnc未授权访问漏洞"


def check_jenkins(ip):
    jenkins_url = f'http://{ip}:8080'
    try:
        response = requests.get(jenkins_url, headers=headers, timeout=5)
        if 'jenkins' in response.headers.get('X-Jenkins', '') and 'Dashboard [Jenkins]' in response.text:
            jobs_url = jenkins_url + "/api/json?tree=jobs[name]"
            jobs_response = requests.get(jobs_url, headers=headers, timeout=5)
            if jobs_response.status_code == 200:
                return f"{ip}[+]*****存在jenkins未授权访问漏洞"
            else:
                return f"{ip}not exist jenkins未授权访问漏洞"
        else:
            return f"{ip}not exist jenkins未授权访问漏洞"
    except:
        return f"{ip}not exist jenkins未授权访问漏洞"


def check_kibana(ip):
    kibana_url = f'http://{ip}:5601'
    endpoints = [
        kibana_url,
        kibana_url + "/app/dashboards",
        kibana_url + "/api/saved_objects/_find?type=dashboard"
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return f"{ip}[+]*****存在kibana未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist kibana未授权访问漏洞"


def check_ipc(ip):
    try:
        import smbclient
        try:
            smbclient.register_session(ip, username='', password='')
            return f"{ip}[+]*****存在ipc未授权访问漏洞"
        except smbclient.AccessDenied:
            return f"{ip}not exist ipc未授权访问漏洞"
        except:
            return f"{ip}not exist ipc未授权访问漏洞"
    except ImportError:
        return f"{ip}缺少 smbclient 库，无法检测 IPC"


def check_druid(ip):
    endpoints = [
        f'http://{ip}:8888/druid/index.html',
        f'http://{ip}:8888/druid/console.html',
        f'http://{ip}:8888/druid/sql.html'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if 'Druid' in response.text:
                return f"{ip}[+]*****存在druid未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist druid未授权访问漏洞"


def check_swaggerui(ip):
    endpoints = [
        ip + '/swagger-ui.html',
        ip + '/v2/api-docs',
        ip + '/swagger-resources'
    ]
    for url in endpoints:
        try:
            swaggerui_response = requests.get(url, headers=headers, timeout=5)
            if 'Swagger' in swaggerui_response.text:
                return f"{ip}[+]*****存在swaggerui未授权访问漏洞"
        except:
            continue
    return "无法连接到 SwaggerUI 应用程序"


def check_docker(ip):
    docker_url = 'http://' + ip + ':2375/version'
    try:
        docker_response = requests.get(docker_url, headers=headers, timeout=5)
        if docker_response.status_code == 200:
            try:
                data = docker_response.json()
                if 'ApiVersion' in data:
                    return f"{ip}[+]*****存在docker未授权访问漏洞"
                else:
                    return f"{ip}not exist docker未授权访问漏洞"
            except json.JSONDecodeError:
                return f"{ip}not exist docker未授权访问漏洞"
        else:
            return f"{ip}not exist docker未授权访问漏洞"
    except:
        return "无法连接到 Docker 守护进程"


def check_rabbitmq(ip):
    endpoints = [
        f'http://{ip}:15672/',
        f'http://{ip}:15672/api/nodes',
        f'http://{ip}:15672/api/queues'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if 'RabbitMQ Management' in response.text and 'overview-module' in response.text:
                return f"{ip}[+]*****存在rabbitmq未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist rabbitmq未授权访问漏洞"


def check_memcached(ip):
    try:
        memcached_client = memcache.Client([ip], timeout=5)
        stats = memcached_client.get_stats()
        settings = memcached_client.get_settings()
        if len(stats) > 0 or len(settings) > 0:
            return f"{ip}[+]*****存在memcached未授权访问漏洞"
        else:
            return f"{ip}not exist memcached未授权访问漏洞"
    except:
        return f"{ip}not exist memcached未授权访问漏洞"


def check_dubbo(ip):
    url = f'http://{ip}:8080/'
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if 'dubbo' in response.headers and 'Welcome to the Dubbo' in response.text:
            return f"{ip}[+]*****存在dubbo未授权访问漏洞"
        else:
            return f"{ip}not exist dubbo未授权访问漏洞"
    except:
        return f"{ip}not exist dubbo未授权访问漏洞"


def check_bt_phpmyadmin(ip):
    endpoints = [
        f'http://{ip}/phpmyadmin/',
        f'http://{ip}/phpmyadmin/index.php',
        f'http://{ip}/phpmyadmin/config.inc.php'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if 'phpMyAdmin' in response.text:
                return f"{ip}[+]*****存在bt_phpmyadmin未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist bt_phpmyadmin未授权访问漏洞"


def check_rsync(ip):
    try:
        import subprocess
        command = f"rsync --list-only rsync://{ip}/"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode == 0:
            return f"{ip}[+]*****存在rsync未授权访问漏洞"
        else:
            return f"{ip}not exist rsync未授权访问漏洞"
    except:
        return f"{ip}not exist rsync未授权访问漏洞"


def check_solr(ip):
    endpoints = [
        f'http://{ip}:8983/solr/',
        f'http://{ip}:8983/solr/admin/',
        f'http://{ip}:8983/solr/select'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if 'Apache Solr' in response.text:
                return f"{ip}[+]*****存在solr未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist solr未授权访问漏洞"


def check_kubernetes_api_server(ip):
    api_server_url = f'https://{ip}:6443/api/'
    try:
        response = requests.get(api_server_url, headers=headers, verify=False, timeout=5)
        if response.status_code == 401:
            return f"{ip}[+]*****存在kubernetes_api_server未授权访问漏洞"
        elif response.status_code == 200:
            try:
                data = response.json()
                if "kind" in data:
                    return f"{ip}[+]*****存在kubernetes_api_server未授权访问漏洞"
                else:
                    return f"{ip}not exist kubernetes_api_server未授权访问漏洞"
            except json.JSONDecodeError:
                return f"{ip}not exist kubernetes_api_server未授权访问漏洞"
        else:
            return f"{ip}not exist kubernetes_api_server未授权访问漏洞"
    except:
        return f"{ip}not exist kubernetes_api_server未授权访问漏洞"


def check_couchdb(ip):
    endpoints = [
        f'http://{ip}:5984/_utils/',
        f'http://{ip}:5984/_all_dbs',
        f'http://{ip}:5984/_stats'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if 'Welcome to CouchDB' in response.text:
                return f"{ip}[+]*****存在couchdb未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist couchdb未授权访问漏洞"


def check_spring_boot_actuator(ip):
    endpoints = [
        f'http://{ip}:8080/actuator/',
        f'http://{ip}:8080/actuator/health',
        f'http://{ip}:8080/actuator/info',
        f'http://{ip}:8080/actuator/env'
    ]
    for url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return f"{ip}[+]*****存在spring_boot_actuator未授权访问漏洞"
        except:
            continue
    return f"{ip}not exist spring_boot_actuator未授权访问漏洞"


# 检查 uWSGI 是否存在未授权访问漏洞
def check_uwsgi(ip):
    uwsgi_url = f'http://{ip}:1717/'
    try:
        response = requests.get(uwsgi_url, headers=headers, timeout=5)
        if 'uWSGI Status' in response.text:
            return f"{ip}[+]*****存在uwsgi未授权访问漏洞"
        else:
            return f"{ip}not exist uwsgi未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 uWSGI 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 uWSGI 服务时出现未知错误: {e}"


# 检查 ThinkAdmin V6 是否存在未授权访问漏洞
def check_thinkadmin_v6(ip):
    thinkadmin_url = f'http://{ip}/index/login.html'
    try:
        response = requests.get(thinkadmin_url, headers=headers, timeout=5)
        if 'ThinkAdmin' in response.text and 'logincheck' in response.text:
            return f"{ip}[+]*****存在thinkadmin_v6未授权访问漏洞"
        else:
            return f"{ip}not exist thinkadmin_v6未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 ThinkAdmin V6 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 ThinkAdmin V6 服务时出现未知错误: {e}"


# 检查 PHP-FPM Fastcgi 是否存在未授权访问漏洞
def check_php_fpm_fastcgi(ip):
    php_fpm_url = f'http://{ip}/php-fpm_status'
    try:
        response = requests.get(php_fpm_url, headers=headers, timeout=5)
        if 'pool:' in response.text and 'processes' in response.text:
            return f"{ip}[+]*****存在php_fpm_fastcgi未授权访问漏洞"
        else:
            return f"{ip}not exist php_fpm_fastcgi未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 PHP-FPM Fastcgi 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 PHP-FPM Fastcgi 服务时出现未知错误: {e}"


# 检查 MongoDB 是否存在未授权访问漏洞
def check_mongodb(ip):
    mongodb_url = f'mongodb://{ip}:27017/'
    try:
        client = pymongo.MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
        dbs = client.list_database_names()
        if len(dbs) > 0:
            return f"{ip}[+]*****存在mongodb未授权访问漏洞"
        else:
            return f"{ip}not exist mongodb未授权访问漏洞"
    except pymongo.errors.ConnectionFailure as e:
        return f"{ip} 连接 MongoDB 服务失败: {e}"
    except Exception as e:
        return f"{ip} 检查 MongoDB 服务时出现未知错误: {e}"


# 检查 Jupyter Notebook 是否存在未授权访问漏洞
def check_jupyter_notebook(ip):
    notebook_url = f'http://{ip}:8888/'
    try:
        response = requests.get(notebook_url, headers=headers, timeout=5)
        if 'Jupyter Notebook' in response.text:
            return f"{ip}[+]*****存在jupyter_notebook未授权访问漏洞"
        else:
            return f"{ip}not exist jupyter_notebook未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Jupyter Notebook 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Jupyter Notebook 服务时出现未知错误: {e}"


# 检查 Apache Spark 是否存在未授权访问漏洞
def check_apache_spark(ip):
    spark_url = f'http://{ip}:8080/'
    try:
        response = requests.get(spark_url, headers=headers, timeout=5)
        if 'Spark Master at' in response.text and 'Workers' in response.text:
            return f"{ip}[+]*****存在apache_spark未授权访问漏洞"
        else:
            return f"{ip}not exist apache_spark未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Apache Spark 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Apache Spark 服务时出现未知错误: {e}"


# 检查 WebLogic 是否存在未授权访问漏洞
def check_weblogic(ip):
    weblogic_url = f'http://{ip}:7001/console/login/LoginForm.jsp'
    try:
        response = requests.get(weblogic_url, headers=headers, timeout=5)
        if 'Oracle WebLogic Server' in response.text:
            return f"{ip}[+]*****存在weblogic未授权访问漏洞"
        else:
            return f"{ip}not exist weblogic未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 WebLogic 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 WebLogic 服务时出现未知错误: {e}"


# 检查 Docker Registry 是否存在未授权访问漏洞
def check_docker_registry(ip):
    registry_url = f'http://{ip}/v2/_catalog'
    try:
        response = requests.get(registry_url, headers=headers, timeout=5)
        if 'repositories' in response.json():
            return f"{ip}[+]*****存在docker_registry未授权访问漏洞"
        else:
            return f"{ip}not exist docker_registry未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Docker Registry 服务时出错: {e}"
    except ValueError as e:
        return f"{ip} 解析 Docker Registry 服务响应时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Docker Registry 服务时出现未知错误: {e}"


# 检查 Hadoop YARN 是否存在未授权访问漏洞
def check_hadoop_yarn(ip):
    yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'
    try:
        response = requests.get(yarn_url, headers=headers, timeout=5)
        if 'resourceManagerVersion' in response.json()['clusterInfo']:
            return f"{ip}[+]*****存在hadoop_yarn未授权访问漏洞"
        else:
            return f"{ip}not exist hadoop_yarn未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Hadoop YARN 服务时出错: {e}"
    except ValueError as e:
        return f"{ip} 解析 Hadoop YARN 服务响应时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Hadoop YARN 服务时出现未知错误: {e}"


# 检查 Kong 是否存在未授权访问漏洞
def check_kong(ip):
    kong_url = f'http://{ip}:8001/'
    try:
        response = requests.get(kong_url, headers=headers, timeout=5)
        if 'Welcome to Kong' in response.text:
            return f"{ip}[+]*****存在kong未授权访问漏洞"
        else:
            return f"{ip}not exist kong未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Kong 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Kong 服务时出现未知错误: {e}"


# 检查 WordPress 是否存在未授权访问漏洞
def check_wordpress(ip):
    wordpress_url = f'http://{ip}/wp-login.php'
    try:
        response = requests.get(wordpress_url, headers=headers, timeout=5)
        if 'WordPress' in response.text:
            return f"{ip}[+]*****存在wordpress未授权访问漏洞"
        else:
            return f"{ip}not exist wordpress未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 WordPress 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 WordPress 服务时出现未知错误: {e}"


# 检查 Zabbix 是否存在未授权访问漏洞
def check_zabbix(ip):
    zabbix_url = f'http://{ip}/zabbix/jsrpc.php'
    try:
        headers = {
            'Content-Type': 'application/json-rpc',
            'User-Agent': 'Mozilla/5.0'
        }
        data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
        response = requests.post(zabbix_url, headers=headers, data=data, timeout=5)
        if 'result' in response.json():
            return f"{ip}[+]*****存在zabbix未授权访问漏洞"
        else:
            return f"{ip}not exist zabbix未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Zabbix 服务时出错: {e}"
    except ValueError as e:
        return f"{ip} 解析 Zabbix 服务响应时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Zabbix 服务时出现未知错误: {e}"


# 检查 Active MQ 是否存在未授权访问漏洞
def check_activemq(ip):
    activemq_url = f'http://{ip}:8161/admin/'
    try:
        response = requests.get(activemq_url, headers=headers, timeout=5)
        if 'Apache ActiveMQ' in response.text:
            return f"{ip}[+]*****存在activemq未授权访问漏洞"
        else:
            return f"{ip}not exist activemq未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Active MQ 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Active MQ 服务时出现未知错误: {e}"


# 检查 Harbor 是否存在未授权访问漏洞
def check_harbor(ip):
    harbor_url = f'http://{ip}/api/v2.0/statistics'
    try:
        response = requests.get(harbor_url, headers=headers, timeout=5)
        if 'total_projects' in response.json():
            return f"{ip}[+]*****存在harbor未授权访问漏洞"
        else:
            return f"{ip}not exist harbor未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Harbor 服务时出错: {e}"
    except ValueError as e:
        return f"{ip} 解析 Harbor 服务响应时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Harbor 服务时出现未知错误: {e}"


# 检查 Atlassian Crowd 是否存在未授权访问漏洞
def check_atlassian_crowd(ip):
    crowd_url = f'http://{ip}:8095/crowd/'
    try:
        response = requests.get(crowd_url, headers=headers, timeout=5)
        if 'Atlassian Crowd' in response.text:
            return f"{ip}[+]*****存在atlassian_crowd未授权访问漏洞"
        else:
            return f"{ip}not exist atlassian_crowd未授权访问漏洞"
    except requests.RequestException as e:
        return f"{ip} 连接 Atlassian Crowd 服务时出错: {e}"
    except Exception as e:
        return f"{ip} 检查 Atlassian Crowd 服务时出现未知错误: {e}"
