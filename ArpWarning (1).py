#elior klein 329843999
#avram harrar 324215458
from scapy.all import *
import sys,subprocess
arpcom=subprocess.Popen(["ip neigh show",">>","listarp"],stdin="PIPE",stdout="PIPE",stderr="PIPE",)
stdout,stderr=arpcom.communicate()
myfile=open("listarp")
mylines=myfile.readlines()
mylist=[]
for i in mylines:
    mylist.append(i)
mylist=mylist[2:]
counter=[]
i=0
for line in mylist:
    mymac=line.split(" ")[1]
    for line1 in mylist:
        mac=line1.split(" ")[1]
        if mac == mymac:
            counter[i]+=1
    i+=1
for count in counter:
    if count>=2:
        print("you are in arp attack")

while True:
	myDict = {}
	for pkt in sniff('arp',count='50'):
		if myDict[pkt[Ether].src] is None:# NUll?
			myDict[pkt[Ether].src] = 1
		else:
			myDict[pkt[Ether].src] += 1

	for key,value in myDict:
		if value >= 20:
			print("the MAC %s is spoofing your IP".format(key))

	sleep(5)

# We had some issues installing the virtual machines so we had no way to check if the code works