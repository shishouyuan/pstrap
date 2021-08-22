#!/usr/bin/python3
import configparser
import logging
import logging.handlers
import os
import re
import socket
import sys
import threading
import time
from datetime import datetime
from typing import List
import struct

app_name='pstrap'

# 默认配置文件位置
defaultConfigDir='/etc/pstrap'
configFileName=os.path.join(defaultConfigDir,'pstrap.ini')
dbFileName=os.path.join(defaultConfigDir,'pstrapped.ini')
dbFileName_cmd=None

# keys in config file
class config_keys:
    trapPorts='trap_ports'
    dbFile='db_file'
    logFile='log_file'
    trappedDuration='trapped_duration'
    trappedTime='trapped_time'
    trappedPort='trapped_port'

class iptables_names:
    trap_port_chain=f'{app_name}_trap_port_allow'
    deny_chian=f'{app_name}_trapped_deny'

# globals variables
trap_ports=[]
db=configparser.ConfigParser()
lock=threading.RLock()
datetime_format='%Y-%m-%dT%H:%M:%S'
trapped_duration=0
cleaner_sleep_time=60
iptables_main_table='filter'
iptables_main_chain='INPUT'

def argSplit(s:str,sep:str=' ',gp:str='"')->List[str]:
    '''Split string at `sep`s that are not enclosed by `gp`.
    Successive `sep`s will be treated as one.
    Leading and tailing `sep`s will be ignored.'''
    r=[]
    v=''
    gpStarted=False
    unitStarted=False
    def next():
        nonlocal v,unitStarted
        unitStarted=False
        r.append(v)
        v=''
    for i in s:
        if i==gp:
            if gpStarted:
                next()
                gpStarted=False
            else:
                gpStarted=True
                unitStarted=True
        elif gpStarted:
            v+=i
        elif unitStarted:
            if i==sep:
                next()
            else:
                v+=i
        else:
            if i!=sep:
                v+=i
                unitStarted=True
    if len(v)>0:
        r.append(v)
    return r

def getRulesFromIptables(table,chain)->list:
    with lock:
        with os.popen(f'iptables -t "{table}" -L "{chain}" -n --line-numbers') as o:
            r=o.read().splitlines()        
        if len(r)<=2:
            return []
        v=[]
        for i in range(2,len(r)):
            t=argSplit(r[i])
            if len(t)>=6:
                v.append({
                    'num':t[0],
                    'target':t[1],
                    'prot':t[2],
                    'opt':t[3],
                    'source':t[4],
                    'destination':t[5],
                    '_others':t[6:] if len(t)>6 else None
                })
        return v

def createChain(name:str, table:str=iptables_main_table)->bool:
    with lock:
        return os.system(f'iptables -t "{table}" -N "{name}"')==0

def removeChain(name:str, table:str=iptables_main_table)->bool:
    with lock:
        if cleanChain(name,table):
            return  os.system(f'iptables -t "{table}" -X "{name}"')==0
        else:
            return False

def cleanChain(name:str, table:str=iptables_main_table)->bool:
    with lock:
        return os.system(f'iptables -t "{table}" -F "{name}"')==0
   
def deleteRuleByNumber(num:int,table:str,chain:str):
    with lock:
        return os.system(f'iptables -t "{table}" -D "{chain}" {num}')
 
def disableChains():
    deleteRule(iptables_main_table,iptables_main_chain,'target',iptables_names.trap_port_chain)  
    deleteRule(iptables_main_table,iptables_main_chain,'target',iptables_names.deny_chian)  
  
def enableChains():
    with lock:        
        os.system(f'iptables -t "{iptables_main_table}" -I "{iptables_main_chain}" -j "{iptables_names.trap_port_chain}"')
        os.system(f'iptables -t "{iptables_main_table}" -I "{iptables_main_chain}" -j "{iptables_names.deny_chian}"')

def initIptables():
    disableChains()
    removeChain(iptables_names.trap_port_chain)
    removeChain(iptables_names.deny_chian)
    createChain(iptables_names.trap_port_chain)
    createChain(iptables_names.deny_chian)
    enableChains()   
    
def deleteRule(table:str,chain:str,field:str,val:str)->int:
    with lock: # rule number may change by other operation
        n=0
        finished=False
        while not finished:
            finished=True
            r=getRulesFromIptables(table,chain)
            for i in r:
                try:
                    if i[field]==val:
                        deleteRuleByNumber(int(i['num']),table,chain)
                        n+=1
                        finished=False
                        break
                except Exception as e:
                    logging.warning(f'Delete rule failed with error {e}')
                    finished=True
                    break            
        return n

def allowPort(port:int,table:str=iptables_main_table,chain:str=iptables_names.trap_port_chain):
    with lock:
        r=os.system(f'iptables -t "{table}" -I "{chain}" -p tcp --dport "{port}" -j ACCEPT ')
        if r==0:           
            logging.debug(f'Added allow rule for port {port}.')
        else:
            logging.warning(f'Failed to add allow rule for port {port} into {table}.{chain} with code {r}.')
    
def denyIP(ip:str,table:str=iptables_main_table,chain:str=iptables_names.deny_chian):   
    with lock: 
        r=os.system(f'iptables -t "{table}" -I "{chain}" -s "{ip}" -j DROP ')
        if r==0:           
            logging.debug(f'Added deny rule for {ip}.')
        else:
            logging.warning(f'Failed to add deny rule for {ip} into {table}.{chain} with code {r}.')

def deleteIPDenyRule(ip:str, table:str=iptables_main_table,chain:str=iptables_names.deny_chian):    
    n=deleteRule(table,chain,'source',ip)  
    logging.debug(f'Deleted {n} deny rule for {ip}.')
    
def initLogging(LogFileName:str)->logging.Logger:    
    formatter = logging.Formatter("%(asctime)s - %(filename)s[%(lineno)d] - %(levelname)s: %(message)s")
    
    fh = logging.handlers.RotatingFileHandler(LogFileName, mode='a', maxBytes=1024*1024*10, backupCount=2,encoding='utf8')
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

def saveDB():    
    
    with lock, open(dbFileName,'w') as dbFile:
            db.write(dbFile)

def cleanOldRules(onlyConfig=False):
    '''清除过期规则，onlyConfig=True时只清除配置文件不处理防火墙'''
    if trapped_duration<=0:
        logging.debug(f'Skip old rules cleaning because {config_keys.trappedDuration}={trapped_duration} is not positive.')
        return

    db_changed=False
    with lock:
        try:
            now=datetime.now()
            for i in db.sections():
                sec=db[i]
                trappedTime=datetime.strptime(sec[config_keys.trappedTime], datetime_format)
                dur=now-trappedTime
                if dur.total_seconds()<0 or dur.total_seconds()/60>trapped_duration:
                    logging.info(f'Rule for {i} expired, which was created at {trappedTime}.' )
                    db.remove_section(i)
                    db_changed=True
                    if not onlyConfig:
                        deleteIPDenyRule(i)
        except Exception as e:
            logging.error(f"Clean old rules error: {e}")
        if db_changed:
            saveDB()

def addTrapPortAllowRules():    
    for i in trap_ports:
        allowPort(i)

def addAllDenyRules():
    for i in db.sections():
        denyIP(i)

def clearAllRule():   
    cleanChain(iptables_names.trap_port_chain)
    cleanChain(iptables_names.deny_chian)

def trapIP(rip:str,rport:int,lip:str,lport:int):
    time=datetime.now().strftime(datetime_format)
    logging.info('Got trapped connection from %s:%d to %s:%d',rip,rport,lip,lport)
    with lock:
        if not db.has_section(rip):
            db.add_section(rip)    
        sec=db[rip]    
        sec[config_keys.trappedTime]=time
        sec[config_keys.trappedPort]=str(lport)                    
    saveDB()
    denyIP(rip)

def listen(ports:List[int]):
    '''listening for trap port'''
    with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP) as sock:
        while True:
            try:
                buf=sock.recv(1000)
                if len(buf)>=20:
                    param={
                        'ver':buf[0]>>4,
                        'head_length':buf[0]&0xf,
                        'total_length':struct.unpack('>H',buf[2:4]),
                        'protocol':buf[9],
                        'src_addr':f'{buf[12]}.{buf[13]}.{buf[14]}.{buf[15]}',
                        'dst_addr':f'{buf[16]}.{buf[17]}.{buf[18]}.{buf[19]}'
                    }
                    tcp_offset=param['head_length']*4
                    if len(buf)>=tcp_offset+4:
                        param['src_port']=struct.unpack('>H',buf[tcp_offset:tcp_offset+2])[0]
                        param['dst_port']=struct.unpack('>H',buf[tcp_offset+2:tcp_offset+4])[0]                        
                        if param['dst_port'] in ports:                            
                            trapIP(param['src_addr'],param['src_port'],param['dst_addr'],param['dst_port']) 
            except Exception as e:
                logging.debug(f'Error occurred when listenning, {e}')

def clean():
    '''cleaning for old rule'''
    while True:
        time.sleep(cleaner_sleep_time)
        cleanOldRules()
        logging.debug(f"Old rule cleaning finished, with {len(db.sections())} remained.")

# 从命令行传入的配置文件路径
def parseArgs():
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

def init():
    global dbFileName, trapped_duration
    try:
        print(f'Reading config file: {configFileName}')        
        config=configparser.ConfigParser(
            defaults={
                config_keys.trapPorts:'',
                config_keys.dbFile:dbFileName,
                config_keys.logFile:'/var/log/pstrap.log',
                config_keys.trappedDuration:str(60*24*7)
                })

        if not os.path.exists(os.path.dirname(configFileName)):
            os.makedirs(os.path.dirname(configFileName))
        config.read(configFileName)
        with open(configFileName,'w') as configFile:
            config.write(configFile)

        defaults=config.defaults()

        initLogging(defaults[config_keys.logFile])   
        logging.info('Program started.')

        for i in re.split(r'\s*,\s*',defaults[config_keys.trapPorts]):
            try:
                p=int(i)
                if p>0 and p not in trap_ports:
                    trap_ports.append(p)
            except Exception:
                continue

        # 规则有效时间  
        trapped_duration=int(defaults[config_keys.trappedDuration])

        # 命令行传入的优先级更高
        if dbFileName_cmd == None:
            dbFileName=defaults[config_keys.dbFile]
        else:
            dbFileName=dbFileName_cmd
        logging.info(f'Config File: {configFileName}, DB File: {dbFileName}')
        logging.info(f'configs: {defaults}')
       
        if not os.path.exists(os.path.dirname(dbFileName)):
            os.makedirs(os.path.dirname(dbFileName))  
                    
        db.read(dbFileName)
    except Exception as e:
        logging.error(f'Init Error, {e}')

    saveDB()

def main():
    parseArgs()
    init()    
    cleanOldRules(True)
    initIptables()
    addAllDenyRules()
    addTrapPortAllowRules()

    cleaningThread=threading.Thread(target=clean)
    cleaningThread.start()
    
    listen(trap_ports)


if __name__=='__main__':
    main()
