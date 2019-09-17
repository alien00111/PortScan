# PortScan
Usage: python pscan.py [OPTION]... 
Implementing Port Scanning
      -p    specify the port of the IP/DNS scan,default full port scan
            python pscan.py 8.8.8.8
            python pscan.py 8.8.8.8 -p 21,80
      -n    specified thread scan
            python pscan.py 8.8.8.8 -p 21,80 -n 50
      -r    specified file scan
            python pscan.py 8.8.8.8 -r 1.txt