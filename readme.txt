How to simulate arp posioning attack in SDN:
==============================================
prereq: ettercap
sudo apt install ettercap-text-only


1. run simple switch application
ryu-manager app.py



2. Run the topology
sudo python3 topology.py



3. Ping h3(192.168.1.3) to h4(192.168.1.4) node continuously.


4. capture traffic in h1 (h1-eth0) and see any traffic 


Now h1 going to act as attacker (MIM)
----------------------------------
 
1. From h1, run the ettercap tool to sniff h3 to h4 traffic , as below


xterm h1
ettercap -T  -i h1-eth1 -w test1.pcap -M ARP  /192.168.1.3// /192.168.1.4//

after few mins, type 'q' to exit the sniff.

2. copy the test.pcap file to host machine and open in Wireshark.
   
Analyze the test.pcap


3. Run other traffic (iperf, http)





How to detect and mitigate the ARP Poisoning attack
===================================================

ONLY DETECTION:


1. Edit app.py and and change ARP_POSION_DETECTION = 1


2. run simple switch application

ryu-manager app.py



3. Run the topology
sudo python3 topology.py


3.xterm h1

4. 
 Ping h3(192.168.1.3) to h4(192.168.1.4) node continuously.


4.
 From h1 (xterm), run the ettercap tool to sniff h3 to h4 traffic , as below


xterm h1
ettercap -T  -i h1-eth1 -w test1.pcap -M ARP  /192.168.1.3// /192.168.1.4//

after few mins, type 'q' to exit the sniff.




DETECTION & MITIGATION
---------------------

1. Edit app.py and and change ARP_POSION_DETECTION = 1 and ARP_POSION_MITIGATION=1


2. run simple switch application

ryu-manager app.py



3. Run the topology
sudo python3 topology.py


3.xterm h1

4. 
 Ping h3(192.168.1.3) to h4(192.168.1.4) node continuously.


4.
 From h1 (xterm), run the ettercap tool to sniff h3 to h4 traffic , as below


xterm h1
ettercap -T  -i h1-eth1 -w test1.pcap -M ARP  /192.168.1.3// /192.168.1.4//

after few mins, type 'q' to exit the sniff.




you can see the DROP rules will get added in the switch to block the h1 port (attacker port)


