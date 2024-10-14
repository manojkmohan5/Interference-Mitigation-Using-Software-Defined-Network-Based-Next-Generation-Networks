#!/usr/bin/python



from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from time import sleep


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', mac="00:00:00:00:00:01", ip="192.168.1.1/24")
        h2 = self.addHost('h2', mac="00:00:00:00:00:02", ip="192.168.1.2/24")
        h3 = self.addHost('h3', mac="00:00:00:00:00:03", ip="192.168.1.3/24")
        h4 = self.addHost('h4', mac="00:00:00:00:00:04", ip="192.168.1.4/24")


        #addlink(hostname,switchname,hostport,switchport)
        self.addLink(h1, s1, 1, 1)
        self.addLink(h2, s1, 1, 2)
        self.addLink(h3, s1, 1, 3)
        self.addLink(h4, s1, 1, 4)


if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    h1 = net.get('h1')
    h1.cmd("sudo tcpdump -i h1-eth1 -B 50 -w test.pcap &")
    sleep(2)
    net.pingAll()
    CLI(net)
    net.stop()
