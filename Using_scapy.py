# -*- coding:utf-8 -*-
#sniff用法参考链接: http://xiaix.me/python-shi-yong-scapy-jin-xing-zhua-bao/
#适用于python 2.x
from scapy.all import *
import time
name=time.ctime()
pktdump=PcapWriter(name+".pcap",append=True,sync=True)

def http_check(string):
    '''
       检查string是否有你想抓取的敏感字符串，返回逻辑1或0
    '''
    sensitive_list=['password','pass','PASSWORD','PASS']
    for s in sensitive_list:
        if s in string:
            return 1
    return 0

def http_print(pkt):
    try:
        http_string=str(pkt[TCP].payload)
    except:
        pass
    else:
        if http_string.find('GET')!=-1 or http_string.find('POST')!=-1:
            if http_check(http_string):
                lines_http_string = http_string.split('\r\n')
                for line in lines_http_string:
                    if http_check(line):
                        print line
    
        

def Packet_Handle(pkt):
    '''
       这个函数定义你想对数据包进行的操作，
       目前这个函数的功能是在终端显示捕获数据包的源IP和目的IP
    '''
    pktdump.write(pkt)
    http_print(pkt)
        
def Capture_On_Interface(interface):
    print "[+]Sarting capturing on "+interface
    pcap=sniff(count=0,store=1,prn=Packet_Handle,iface=interface)
    print "[+]exit normally"

        


if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A small tool to capture packets")
    parser.add_argument("--iface","-i",default='eth0',help="specify an interface name(Default:eth0)")
    args = parser.parse_args()
    Capture_On_Interface(args.iface)
    
        
        


    
    
