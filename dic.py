import ftplib
import socket
from config import *
import memcache as memcache
import pymongo as pymongo
import requests

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

def check_elasticsearch(ip):
    url = f'http://{ip}:9200/_cat'
    try:
        response = requests.get(url,headers=headers, timeout=5)
        if '/_cat/master' in response.text:
            return f"{ip}[+]*****存在elasticsearch未授权访问漏洞"
        else:
            return f"{ip}not exist elasticsearch未授权访问漏洞"
    except:
        return "无法连接到elasticsearch服务"

def check_jboss(ip):
    

    # 检查 JBoss 是否存在未授权访问漏洞
    jboss_url = f'http://{ip}:8080/jmx-console/'
    try:
        jboss_response = requests.get(jboss_url,headers=headers)
        if 'jboss' in jboss_response.headers.get('Server', '') and 'Welcome to JBossAS' in jboss_response.text:
            return f"{ip}[+]*****存在jboss未授权访问漏洞"
        else:
            return f"{ip}not exist jboss未授权访问漏洞"
    except:
        return "无法连接到 jboss 服务"


def check_ldap(ip):
    

    # 检查 LDAP 是否存在未授权访问漏洞
    ldap_url = f'http://{ip}:389'
    try:
        ldap_response = requests.get(ldap_url)
        if 'OpenLDAP' in ldap_response.headers.get('Server', '') and '80090308' in ldap_response.text:
            return f"{ip}[+]*****存在ldap未授权访问漏洞"
        else:
            return f"{ip}not exist ldap未授权访问漏洞"
    except:
        return "无法连接到 ldap 服务"


def check_redis(ip):
    

    # 检查 Redis 是否存在未授权访问漏洞
    redis_url = ip + ':6379/info'
    try:
        redis_response = requests.get(redis_url,headers=headers, allow_redirects=False)
        if redis_response.status_code == 200 and 'redis_version' in redis_response.text:
            return f"{ip}[+]*****存在redis未授权访问漏洞"
        else:
            return f"{ip}not exist redis未授权访问漏洞"
    except:
        return f"{ip}not exist redis未授权访问漏洞"
def check_nfs(ip):
    

    # 检查 NFS 是否存在未授权访问漏洞
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

    # 检查 FTP 是否存在未授权访问漏洞
    try:
        ftp = ftplib.FTP(ip)
        ftp.login()
        ftp.cwd('/')
        ftp.quit()
        return f"{ip}[+]*****存在ftp未授权访问漏洞"
    except:
        return f"{ip}not exist ftp未授权访问漏洞"


def check_zookeeper(ip):
    
    # 检查 Zookeeper 是否存在未授权访问漏洞
    zookeeper_url = f'http://{ip}:2181/'
    try:
        zookeeper_response = requests.get(zookeeper_url,headers=headers, timeout=5)
        if 'Zookeeper' in zookeeper_response.headers.get('Server',
                                                         '') and zookeeper_response.status_code == 200:
            return f"{ip}[+]*****存在zookeeper未授权访问漏洞"
        else:
            return f"{ip}not exist zookeeper未授权访问漏洞"
    except:
        return "无法连接到 Zookeeper 服务"


# 检查 VNC 是否存在未授权访问漏洞
def check_vnc(ip):
    
    vnc_url = f'vnc://{ip}'
    try:
        tigerVNC_response = requests.get(vnc_url, timeout=5)
        if "RFB 003.008\n" in tigerVNC_response.content.decode('utf-8'):
            return f"{ip}[+]*****存在vnc未授权访问漏洞"
        else:
            return f"{ip}not exist vnc未授权访问漏洞"
    except:
        return f"{ip}not exist vnc未授权访问漏洞"


# 检查 Jenkins 是否存在未授权访问漏洞
def check_jenkins(ip):
    
    jenkins_url = f'http://{ip}:8080'
    try:
        response = requests.get(jenkins_url,headers=headers, timeout=5)
        if 'jenkins' in response.headers.get('X-Jenkins', '') and 'Dashboard [Jenkins]' in response.text:
            return f"{ip}[+]*****存在jenkins未授权访问漏洞"
        else:
            return f"{ip}not exist jenkins未授权访问漏洞"
    except:
        return f"{ip}not exist jenkins未授权访问漏洞"



# 检查 Kibana 是否存在未授权访问漏洞
def check_kibana(ip):
    
    kibana_url = f'http://{ip}:5601'
    try:
        response = requests.get(kibana_url,headers=headers, timeout=5)
        if 'kbn-name="kibana"' in response.text:
            return f"{ip}[+]*****存在kibana未授权访问漏洞"
        else:
            return f"{ip}not exist kibana未授权访问漏洞"
    except:
        return f"{ip}not exist kibana未授权访问漏洞"



# 检查 IPC 是否存在未授权访问漏洞
def check_ipc(ip):
    
    ipc_url = f'http://{ip}:445'
    try:
        response = requests.get(ipc_url,headers=headers, timeout=5)
        if 'IPC Service' in response.text:
            return f"{ip}[+]*****存在ipc未授权访问漏洞"
        else:
            return f"{ip}not exist ipc未授权访问漏洞"
    except:
        return f"{ip}not exist ipc未授权访问漏洞"



# 检查 Druid 是否存在未授权访问漏洞
def check_druid(ip):
    
    druid_url = f'http://{ip}:8888/druid/index.html'
    try:
        response = requests.get(druid_url,hearders=headers, timeout=5)
        if 'Druid Console' in response.text:
            return f"{ip}[+]*****存在druid未授权访问漏洞"
        else:
            return f"{ip}not exist druid未授权访问漏洞"
    except:
        return f"{ip}not exist druid未授权访问漏洞"



def check_swaggerui(ip):
    
    # 检查 SwaggerUI 是否存在未授权访问漏洞
    swaggerui_url = ip + '/swagger-ui.html'
    try:
        swaggerui_response = requests.get(swaggerui_url,hearders=headers, timeout=5)
        if 'Swagger' in swaggerui_response.text:
            return f"{ip}[+]*****存在swaggerui未授权访问漏洞"
        else:
            return f"{ip}not exist swaggerui未授权访问漏洞"
    except:
        return "无法连接到 SwaggerUI 应用程序"

def check_docker(ip):
    
    # 检查 Docker 是否存在未授权访问漏洞
    docker_url = 'http://' + ip + ':2375/version'
    try:
        docker_response = requests.get(docker_url,hearders=headers, timeout=5)
        if docker_response.status_code == 200 and 'ApiVersion' in docker_response.json():
            return f"{ip}[+]*****存在docker未授权访问漏洞"
        else:
            return f"{ip}not exist docker未授权访问漏洞"
    except:
        return "无法连接到 Docker 守护进程"

# 检查 RabbitMQ 是否存在未授权访问漏洞
def check_rabbitmq(ip):
    
    rabbitmq_url = f'http://{ip}:15672/'

    try:
        response = requests.get(rabbitmq_url,hearders=headers, timeout=5)
        if 'RabbitMQ Management' in response.text and 'overview-module' in response.text:
            return f"{ip}[+]*****存在rabbitmq未授权访问漏洞"
        else:
            return f"{ip}not exist rabbitmq未授权访问漏洞"
    except:
        return f"{ip}not exist rabbitmq未授权访问漏洞"



# 检查 Memcached 是否存在未授权访问漏洞
def check_memcached(ip):
    

    try:
        memcached_client = memcache.Client([ip], timeout=5)
        stats = memcached_client.get_stats()
        if len(stats) > 0:
            return f"{ip}[+]*****存在memcached未授权访问漏洞"
        else:
            return f"{ip}not exist memcached未授权访问漏洞"
    except:
        return f"{ip}not exist memcached未授权访问漏洞"

# 检查 Dubbo 是否存在未授权访问漏洞
def check_dubbo(ip):
    
    url = f'http://{ip}:8080/'
    try:
        response = requests.get(url,hearders=headers, timeout=5)
        if 'dubbo' in response.headers and 'Welcome to the Dubbo' in response.text:
            return f"{ip}[+]*****存在dubbo未授权访问漏洞"
        else:
            return f"{ip}not exist dubbo未授权访问漏洞"
    except:
        return f"{ip}not exist dubbo未授权访问漏洞"

# 检查宝塔phpmyadmin是否存在未授权访问漏洞
def check_bt_phpmyadmin(ip):
    
    phpmyadmin_url = f'http://{ip}/phpmyadmin/'
    try:
        response = requests.get(phpmyadmin_url,hearders=headers, timeout=5)
        if 'phpMyAdmin' in response.text:
            return f"{ip}[+]*****存在bt_phpmyadmin未授权访问漏洞"
        else:
            return f"{ip}not exist bt_phpmyadmin未授权访问漏洞"
    except:
        return f"{ip}not exist bt_phpmyadmin未授权访问漏洞"


# 检查 Rsync 是否存在未授权访问漏洞
def check_rsync(ip):
    
    rsync_url = f'rsync://{ip}'
    try:
        response = requests.get(rsync_url,hearders=headers, timeout=5)
        if 'rsync' in response.headers.get('Server', '') and 'rsyncd.conf' in response.text:
            return f"{ip}[+]*****存在rsync未授权访问漏洞"
        else:
            return f"{ip}not exist rsync未授权访问漏洞"
    except:
        return f"{ip}not exist rsync未授权访问漏洞"


# 检查 Solr 是否存在未授权访问漏洞
def check_solr(ip):
    
    solr_url = f'http://{ip}:8983/solr/'
    try:
        response = requests.get(solr_url,hearders=headers, timeout=5)
        if 'Apache Solr' in response.text:
            return f"{ip}[+]*****存在solr未授权访问漏洞"
        else:
            return f"{ip}not exist solr未授权访问漏洞"

    except:
        return f"{ip}not exist solr未授权访问漏洞"


# 检查 Kubernetes Api Server 是否存在未授权访问漏洞
def check_kubernetes_api_server(ip):
    
    api_server_url = f'https://{ip}:6443/api/'

    try:
        response = requests.get(api_server_url,hearders=headers, verify=False, timeout=5)
        if 'Unauthorized' in response.text:
            return f"{ip}[+]*****存在kubernetes_api_server未授权访问漏洞"
        else:
            return f"{ip}not exist kubernetes_api_server未授权访问漏洞"
    except:
        return f"{ip}not exist kubernetes_api_server未授权访问漏洞"



# 检查 CouchDB 是否存在未授权访问漏洞
def check_couchdb(ip):
    
    couchdb_url = f'http://{ip}:5984/_utils/'

    try:
        response = requests.get(couchdb_url,hearders=headers, timeout=5)
        if 'Welcome to CouchDB' in response.text:
            return f"{ip}[+]*****存在couchdb未授权访问漏洞"
        else:
            return f"{ip}not exist couchdb未授权访问漏洞"
    except:
        return f"{ip}not exist couchdb未授权访问漏洞"



# 检查 Spring Boot Actuator 是否存在未授权访问漏洞
def check_spring_boot_actuator(ip):
    
    actuator_url = f'http://{ip}:8080/actuator/'

    try:
        response = requests.get(actuator_url,hearders=headers, timeout=5)
        if 'Hystrix' in response.text and 'health" : {' in response.text:
            return f"{ip}[+]*****存在spring_boot_actuator未授权访问漏洞"
        else:
            return f"{ip}not exist spring_boot_actuator未授权访问漏洞"
    except:
        return f"{ip}not exist spring_boot_actuator未授权访问漏洞"



# 检查 uWSGI 是否存在未授权访问漏洞
def check_uwsgi(ip):
    
    uwsgi_url = f'http://{ip}:1717/'

    try:
        response = requests.get(uwsgi_url,hearders=headers, timeout=5)
        if 'uWSGI Status' in response.text:
            return f"{ip}[+]*****存在uwsgi未授权访问漏洞"
        else:
            return f"{ip}not exist uwsgi未授权访问漏洞"
    except:
        return f"{ip}not exist uwsgi未授权访问漏洞"



# 检查 ThinkAdmin V6 是否存在未授权访问漏洞
def check_thinkadmin_v6(ip):
    
    thinkadmin_url = f'http://{ip}/index/login.html'

    try:
        response = requests.get(thinkadmin_url,hearders=headers, timeout=5)
        if 'ThinkAdmin' in response.text and 'logincheck' in response.text:
            return f"{ip}[+]*****存在thinkadmin_v6未授权访问漏洞"
        else:
            return f"{ip}not exist thinkadmin_v6未授权访问漏洞"
    except:
        return f"{ip}not exist thinkadmin_v6未授权访问漏洞"


# 检查 PHP-FPM Fastcgi 是否存在未授权访问漏洞
def check_php_fpm_fastcgi(ip):
    
    php_fpm_url = f'http://{ip}/php-fpm_status'

    try:
        response = requests.get(php_fpm_url,hearders=headers, timeout=5)
        if 'pool:' in response.text and 'processes' in response.text:
            return f"{ip}[+]*****存在php_fpm_fastcgi未授权访问漏洞"
        else:
            return f"{ip}not exist php_fpm_fastcgi未授权访问漏洞"
    except:
        return f"{ip}not exist php_fpm_fastcgi未授权访问漏洞"



# 检查 MongoDB 是否存在未授权访问漏洞
def check_mongodb(ip):
    
    mongodb_url = f'mongodb://{ip}:27017/'

    try:
        client = pymongo.MongoClient(mongodb_url,hearders=headers, serverSelectionTimeoutMS=5000)
        dbs = client.list_database_names()
        if len(dbs) > 0:
            return f"{ip}[+]*****存在mongodb未授权访问漏洞"
        else:
            return f"{ip}not exist mongodb未授权访问漏洞"
    except:
        return f"{ip}not exist mongodb未授权访问漏洞"


# 检查 Jupyter Notebook 是否存在未授权访问漏洞
def check_jupyter_notebook(ip):
    
    notebook_url = f'http://{ip}:8888/'

    try:
        response = requests.get(notebook_url,hearders=headers, timeout=5)
        if 'Jupyter Notebook' in response.text:
            return f"{ip}[+]*****存在jupyter_notebook未授权访问漏洞"
        else:
            return f"{ip}not exist jupyter_notebook未授权访问漏洞"
    except:
        return f"{ip}not exist jupyter_notebook未授权访问漏洞"



# 检查 Apache Spark 是否存在未授权访问漏洞
def check_apache_spark(ip):
    
    spark_url = f'http://{ip}:8080/'

    try:
        response = requests.get(spark_url,hearders=headers, timeout=5)
        if 'Spark Master at' in response.text and 'Workers' in response.text:
            return f"{ip}[+]*****存在apache_spark未授权访问漏洞"
        else:
            return f"{ip}not exist apache_spark未授权访问漏洞"
    except:
        return f"{ip}not exist apache_spark未授权访问漏洞"


# 检查 WebLogic 是否存在未授权访问漏洞
def check_weblogic(ip):
    
    weblogic_url = f'http://{ip}:7001/console/login/LoginForm.jsp'

    try:
        response = requests.get(weblogic_url,hearders=headers, timeout=5)
        if 'Oracle WebLogic Server' in response.text:
            return f"{ip}[+]*****存在weblogic未授权访问漏洞"
        else:
            return f"{ip}not exist weblogic未授权访问漏洞"
    except:
        return f"{ip}not exist weblogic未授权访问漏洞"


# 检查 Docker Registry 是否存在未授权访问漏洞
def check_docker_registry(ip):
    
    registry_url = f'http://{ip}/v2/_catalog'

    try:
        response = requests.get(registry_url,hearders=headers, timeout=5)
        if 'repositories' in response.json():
            return f"{ip}[+]*****存在docker_registry未授权访问漏洞"
        else:
            return f"{ip}not exist docker_registry未授权访问漏洞"
    except:
        return f"{ip}not exist docker_registry未授权访问漏洞"



# 检查 Hadoop YARN 是否存在未授权访问漏洞
def check_hadoop_yarn(ip):
    
    yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'

    try:
        response = requests.get(yarn_url,hearders=headers, timeout=5)
        if 'resourceManagerVersion' in response.json()['clusterInfo']:
            return f"{ip}[+]*****存在hadoop_yarn未授权访问漏洞"
        else:
            return f"{ip}not exist hadoop_yarn未授权访问漏洞"
    except:
        return f"{ip}not exist hadoop_yarn未授权访问漏洞"


# 检查 Kong 是否存在未授权访问漏洞
def check_kong(ip):
    
    kong_url = f'http://{ip}:8001/'

    try:
        response = requests.get(kong_url,hearders=headers, timeout=5)
        if 'Welcome to Kong' in response.text:
            return f"{ip}[+]*****存在kong未授权访问漏洞"
        else:
            return f"{ip}not exist kong未授权访问漏洞"
    except:
        return f"{ip}not exist kong未授权访问漏洞"



# 检查 WordPress 是否存在未授权访问漏洞
def check_wordpress(ip):
    
    wordpress_url = f'http://{ip}/wp-login.php'

    try:
        response = requests.get(wordpress_url,hearders=headers, timeout=5)
        if 'WordPress' in response.text:
            return f"{ip}[+]*****存在wordpress未授权访问漏洞"
        else:
            return f"{ip}not exist wordpress未授权访问漏洞"
    except:
        return f"{ip}not exist wordpress未授权访问漏洞"


# 检查 Zabbix 是否存在未授权访问漏洞
def check_zabbix(ip):
    
    zabbix_url = f'http://{ip}/zabbix/jsrpc.php'

    try:
        headers = {
            'Content-Type': 'application/json-rpc',
            'User-Agent': 'Mozilla/5.0'
        }
        data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
        response = requests.post(zabbix_url,headers=headers, data=data, timeout=5)
        if 'result' in response.json():
            return f"{ip}[+]*****存在zabbix未授权访问漏洞"
        else:
            return f"{ip}not exist zabbix未授权访问漏洞"
    except:
        return f"{ip}not exist zabbix未授权访问漏洞"

# 检查 Active MQ 是否存在未授权访问漏洞
def check_activemq(ip):
    
    activemq_url = f'http://{ip}:8161/admin/'

    try:
        response = requests.get(activemq_url,hearders=headers, timeout=5)
        if 'Apache ActiveMQ' in response.text:
            return f"{ip}[+]*****存在activemq未授权访问漏洞"
        else:
            return f"{ip}not exist activemq未授权访问漏洞"
    except:
        return f"{ip}not exist activemq未授权访问漏洞"


# 检查 Harbor 是否存在未授权访问漏洞
def check_harbor(ip):
    
    harbor_url = f'http://{ip}/api/v2.0/statistics'

    try:
        response = requests.get(harbor_url,hearders=headers, timeout=5)
        if 'total_projects' in response.json():
            return f"{ip}[+]*****存在harbor未授权访问漏洞"
        else:
            return f"{ip}not exist harbor未授权访问漏洞"
    except:
        return f"{ip}not exist harbor未授权访问漏洞"



# 检查 Atlassian Crowd 是否存在未授权访问漏洞
def check_atlassian_crowd(ip):
    
    crowd_url = f'http://{ip}:8095/crowd/'

    try:
        response = requests.get(crowd_url,hearders=headers, timeout=5)
        if 'Atlassian Crowd' in response.text:
            return f"{ip}[+]*****存在atlassian_crowd未授权访问漏洞"
        else:
            return f"{ip}not exist atlassian_crowd未授权访问漏洞"
    except:
        return f"{ip}not exist atlassian_crowd未授权访问漏洞"

