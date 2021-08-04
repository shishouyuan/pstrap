#! /bin/python3
import configparser
import logging
import logging.handlers
import os
import re
import socket
import sys
import threading
import time
from datetime import date, datetime


def initLogging(LogFileName:str)->logging.Logger:
    '''初始化日志记录模块'''
    formatter = logging.Formatter("%(asctime)s - %(filename)s[%(lineno)d] - %(levelname)s: %(message)s")
    
    fh = logging.handlers.RotatingFileHandler(LogFileName, mode='a', maxBytes=10240, backupCount=2,encoding='utf8')
    fh.setLevel(logging.INFO)  
    fh.setFormatter(formatter)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) 
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# 默认配置文件位置
defaultConfigDir='/etc/pstrap'
configFileName=os.path.join(defaultConfigDir,'pstrap.ini')
dbFileName=os.path.join(defaultConfigDir,'pstrapped.ini')
dbFileName_cmd=None

# 从命令行传入的配置文件路径
for i in range(1,len(sys.argv)):
    cv=sys.argv[i]
    if cv=='-c':
        if len(sys.argv)>i+1:
            i+=1
            configFileName=sys.argv[i]
            continue
        else:
            print('-c arg not given.')
            sys.exit(-1)
    if cv=='-d':
        if len(sys.argv)>i+1:
            i+=1
            dbFileName_cmd=sys.argv[i]
            continue
        else:
            print('-d arg not given.')
            sys.exit(-1)
 

# 配置文件中的键
class keys:
    trapPorts='trap_ports'
    dbFile='db_file'
    logFile='log_file'
    trappedDuration='trapped_duration'
    trappedTime='trapped_time'
    trappedPort='trapped_port'
    


# 读取配置文件
try:
    print(f'Reading config file: {configFileName}')

    config=configparser.ConfigParser(
        defaults={
            keys.trapPorts:'',
            keys.dbFile:dbFileName,
            keys.logFile:'/var/log/pstrap.log',
            keys.trappedDuration:60*24*7
            })

    if not os.path.exists(os.path.dirname(configFileName)):
        os.mkdir(os.path.dirname(configFileName))
    config.read(configFileName)
    with open(configFileName,'w') as configFile:
        config.write(configFile)

    defaults=config.defaults()

    initLogging(defaults[keys.logFile])

    trapPorts=[]
    for i in re.split('\s*,\s*',defaults[keys.trapPorts]):
        try:
            p=int(i)
            if p>0 and p not in trapPorts:
                trapPorts.append(p)
        except Exception:
            continue

    # 规则有效时间  
    trappedDuration=int(defaults[keys.trappedDuration])

    # 命令行传入的优先级更高
    if dbFileName_cmd == None:
        dbFileName=defaults[keys.dbFile]
    else:
        dbFileName=dbFileName_cmd
    logging.debug(f'config file: {configFileName}, db file: {dbFileName}')
    logging.info(f'Trap ports: {trapPorts}')

    if not os.path.exists(os.path.dirname(dbFileName)):
        os.mkdir(os.path.dirname(dbFileName))   
    db=configparser.ConfigParser()
    db.read(dbFileName)
except Exception as e:
    logging.error(f'Init Error, {e}')

ruleComment='pstrap rule'

lock=threading.Lock()

datetimeFormat='%Y-%m-%dT%H:%M:%S'


def saveDB():
    ''' 将规则保存的配置文件'''
    lock.acquire()
    with open(dbFileName,'w') as dbFile:
        db.write(dbFile)
    lock.release()
saveDB()


def cleanOldRules(onlyConfig=False):
    '''清除过期规则，onlyConfig=True时只清除配置文件不处理防火墙'''
    lock.acquire()
    try:
        now=datetime.now()
        for i in db.sections():
            sec=db[i]
            dur=now-datetime.strptime(sec[keys.trappedTime], datetimeFormat)
            if dur.total_seconds()<0 or dur.total_seconds()/60>trappedDuration:
                logging.info(f'Rule for {i} expired.' )
                db.remove_section(i)
                if not onlyConfig:
                    deleteIPRule(i)
    except Exception as e:
        logging.error(f"Clean old rules error: {e}")

    lock.release()
    saveDB()

def addAllRule(): 
    '''把所有规则加入防火墙'''   
    for i in trapPorts:# 允许陷阱端口
        allowPort(i)
    for i in db.sections():
        denyIP(i,db[i][keys.trappedTime])

def allowPort(port:int):
    lock.acquire()
    os.system(f'ufw insert 1 allow "{port}/tcp" comment "{ruleComment}"')
    lock.release()

def denyIP(ip:str, time:datetime):   
    lock.acquire() 
    r=os.popen(f'ufw insert 1 deny from "{ip}" comment "{ruleComment} {time}"').read()
    logging.debug('Added deny rule for %s. ufw result:\n%s', ip, r)
    lock.release()

def deleteIPRule(ip:str):

    lock.acquire()
    n=0
    while True:
        r=os.popen('ufw status numbered').read()
        m=re.search(r'^\[\s*(\d+)\s*\].*?{}.*?#\s*{}.*$'.format(ip,ruleComment),r,flags=re.MULTILINE)
        print(m)
        if m:
            os.system(f'echo y | ufw delete "{m.groups(0)[0]}"')
            n+=1
        else:
            break    
    logging.debug("%d rule for %s deleted.",n,ip)
    lock.release()

def clearAllRule():
    '''删除所有备注匹配的规则'''
    lock.acquire()
    n=0
    while True:
        r=os.popen('ufw status numbered').read()
        m=re.search(r'^\[\s*(\d+)\s*\].*?#.*{}.*$'.format(ruleComment),r,flags=re.MULTILINE)
        if m:
            os.system(f'echo y | ufw delete "{m.groups(0)[0]}"')
            n+=1
        else:
            break    
    logging.debug("Rule cleared. %d deleted.",n)
    lock.release()

def listen(port:int):
    '''各端口监听线程'''
    with socket.socket() as s:
        try:
            s.bind(('0.0.0.0',port))
            s.listen()
        except Exception as e:
            logging.error(f"Port {port} binding error: {e}")
            return
        while True:
            cs,addr=s.accept()
            rip,rport=addr
            lip,lport=cs.getsockname()
            time=datetime.now().strftime(datetimeFormat)
            logging.info('Got trapped connection from %s:%d to %s:%d',rip,rport,lip,lport)

            lock.acquire()
            if not db.has_section(rip):
                db.add_section(rip)    
            sec=db[rip]    
            sec[keys.trappedTime]=time
            sec[keys.trappedPort]=str(lport)
            lock.release()  
            saveDB()
            denyIP(rip,time) 

cleanerSleepTime=60
def cleaner():
    '''过期规则清理线程'''
    while True:
        time.sleep(cleanerSleepTime)
        cleanOldRules()
        logging.debug("Old rule cleaning finished.")

#for i in trapPorts:

cleanOldRules(True)
clearAllRule()
addAllRule()

threads={}
for i in trapPorts:
    t=threading.Thread(target=listen,args=(i,))    
    t.start()
    threads[i]=t

cleaningThread=threading.Thread(target=cleaner)
cleaningThread.start()
cleaningThread.join()
