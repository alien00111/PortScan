import socket
import threading
import optparse
from optparse import OptionParser
import re
import queue
RED='\033[1;31m'
GREE='\033[1;32m'
YELL='\033[1;33m'
que=queue.Queue()
USAGE='''
Usage:python pscan.py 8.8.8.8
      python pscan.py 8.8.8.8 -p 21,80
      python pscan.py 8.8.8.8 -p 21,80 -n 50
'''
#定义一个scanner类，传入一个对象
class Scanner(object):
    #定义初始化方法，传入参数ip,端口，进程
    def __init__(self,target,port,threadnum=100):
        self.target = target
        self.port = port
        self.threadnum = threadnum
        if self.file()==True:
            fileList=self.openFile()
            print(self.open())
            for i in fileList:
                if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",i):
                    self.target=target
                    self.start()
                elif re.match(r"^[a-zA-Z0-9]{2,10}\.[a-zA-Z0-9]{2,10}\.[a-zA-Z0-9]{2,10}",i):
                    self.target=target
                    self.start()
                else:
                    print("不合法的文件")
                    exit()
        else:
            #用re模块的target进行正则表达式匹配Ipv4地址,如果正则匹配住就赋值，否则ip不合法退出程序
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",target):
                self.target=target
            elif self.dns()==True:
                self.target=socket.gethostbyname(args[0])
            else:
                print("不合法的输入")
                exit()
            #对端口和进程进行赋值

    def open(self):
        text = self.openFile()
        for i in text:
            self.target = i

    def dns(self):
        try:
            if re.match(r"^[a-zA-Z0-9]{2,10}\.[a-zA-Z0-9]{2,10}\.[a-zA-Z0-9]{2,10}",self.target):
                return True
            else:
                return False
        except Exception:
            print("域名不合法")
            pass
        #定义start方法，为了实现开始进行端口扫描功能
    def file(self):
        try:
            if re.match(r"^.*\.txt",self.target):
                return True
            else:
                return False
        except Exception:
            print("文件不合法")
            pass

    def openFile(self):
        IP = []
        print(self.target)
        f = open(self.target,'r')
        data = f.read()
        f.close()
        iplist = re.findall(r'\d+\.\d+\.\d+\.\d+', data)
        for i in iplist:
            if i not in IP:
                IP.append(i)
        return IP
    def start(self):
        if self.port==65535:        #如果没有输入端口，默认是65535,进入到这里，循环向队列赋值
            for i in range(65536):
                que.put(i)      #向队列发送端口
        else:
            for i in self.port:     #否则检测用户的输入的端口有无语法错误
                if int(i)<0 or int(i)>65535:        #如果没有在1-65535之间，提示错误并且退出程序
                    print(RED+"必须是0-65535之间的端口")
                    exit()
                que.put(i)      #将没有错误的端口向队列里传值，传端口值
        try:
            print("正在扫描%s"%self.target) #格式化输出ip
            thread_pool=[]      #建一个线程池
            for i in range(0,int(self.threadnum)):      #一个线程对应一个ip,遍历指定的进程数
                th=threading.Thread(target=self.run,args=())   #创建一个线程，
                thread_pool.append(th)          #向线程池添加线程
            for th in thread_pool:      #遍历线程池
                th.setDaemon(True)      #守护进程，伴随主线程存亡
                th.start()              #启动线程
            que.join()      #对主线程进行阻塞，子线程说自己还没运行完，主线程等待
            print("完成扫描")
        except Exception as e:  #如果有异常就继续执行
            pass
        except KeyboardInterrupt:   #如果动了键盘就是用户自动退出
            print(RED + "用户自动退出扫描")

    def run(self):          #定义一个run函数
        while not  que.empty():     #当队列不为空的时候
            port=int(que.get())     #接受端口值给port
            if self.portScan(port):     #
                banner=self.getSocketBanner(port)
                if banner:
                    print(GREE+"%d---open   "%(port))
                else:
                    print(GREE +"%d---open   "%(port))
            que.task_done()

    def portScan(self,port):    #定义portscan函数
        try:
            sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)     #创建socket对象AF_INET：使用IPv4；SOCK_STREAM：TCP套接字类型
            sk.settimeout(5)        #设置延时
            if sk.connect_ex((self.target,port))==0:   #连接到处self.target,port的套接字。self.target,port的格式为元组（hostname,port），如果正确返回0 错误返回1
                return True
            else:
                return False
        except Exception as e:          #遇到异常抛出异常，pass
            print("portscan:error",e)
            pass
        except KeyboardInterrupt:       #用户终止
            print(RED+"用户自动退出扫描")
        finally:
            sk.close()

    def getSocketBanner(self,port):
        try:
            sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)#创建socket对象AF_INET：使用IPv4；SOCK_STREAM：TCP套接字类型
            sk.settimeout(0.5)
            sk.connect(self.target,port)        #连接端口
            sk.send("Hello\r\n".encode("utf-8"))#发一个hello
            return sk.recv(2048).decode("utf-8")#接受套接字的数据。数据以字符串形式返回，bufsize（2048）指定最多可以接收的数量。
        except Exception as e:
            pass
        finally:
            sk.close()


#为用户提供界面
parser=optparse.OptionParser()
#创建一个optparse对象，optParser.parse_args() 剖析并返回一个字典和列表
#字典中的关键字是我们所有的add_option()函数中的dest参数值
#add_option()参数说明：
        #action:存储方式，分为三种store、store_false、store_true
        #type:类型
        #dest:存储的变量
        #default:默认值
        #help:帮助信息
parser.add_option('-p','--port',action="store",type="str",dest="port",help="All ports to be scanned default all port")
parser.add_option('-n','--num',action="store",type="int",dest="threadnum",help="Thread num default 100")
#parser.add_option('-l','--list',action="store",type="str",dest="text",help="Specifies the program to run")
parser.add_option('-u','--url',action="store",type="str",dest="url",help="Specifies url to run")
#由用户传入optParser.parse_args()的参数
(option,args)=parser.parse_args()
#如果没输入端口没有线程只输入了ip
if option.port==None and option.threadnum==None and len(args)==1:
    scanner=Scanner(args[0],65535)#扫描ip的默认全端口扫描
    scanner.start()#调用开始函数执行扫描
#如果输入端口和ip没有进程
elif option.port!=None and option.threadnum==None and len(args) ==1:
    port = option.port.split()#如果说输入了端口就讲输入的东西返回列表
    scanner=Scanner(args[0],port)#扫描ip与指定端口
    scanner.start()#调用开始函数执行扫描
#如果输入ip和进程数
elif option.port==None and option.threadnum!=None and len(args) ==1:
    scanner=Scanner(args[0],65535,option.threadnum)
#如果ip进程和端口都写入
elif option.port!=None and option.threadnum!=None and len(args) ==1:
    port=option.port.split()
    scanner=Scanner(args[0],port,option.threadnum)
elif option.port!=None and option.threadnum==None and option.url!=None:
    port = option.port.split()
    scanner=Scanner(option.url,port)
    #scanner.openFile()
    scanner.start()
elif option.port==None and option.threadnum==None and option.url!=None:
    scanner=Scanner(option.url,65535)
else:
#否则输出帮助信息
    print(GREE+USAGE+GREE)
    parser.print_help()
