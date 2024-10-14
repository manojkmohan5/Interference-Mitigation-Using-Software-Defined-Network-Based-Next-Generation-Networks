from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4

ARP_POSION_DETECTION = 1
ARP_POSION_MITIGATION = 1


class MySwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_ip = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        #add a static flow for ARP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath, 100, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_t=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority,  idle_timeout=idle_t, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_t,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    def arp_process(self, a, dpid, in_port):
        '''
        Input:  ARP Packet, switch id, input port
        Output: True  (if geninue ARP), FALSE (ARP posion attack)
        Algorithm:
        ==========
        1. Building the ARP Table (mac is key, ip and port number are elements.)
        2. When the ARP Packet gets in, check the src mac against the Table
            if mac is not present in the table 
                its a new entry, add with ip and mac
            if mac is present in the table,
                 check the src ip, in port against the stored one,
                 if it is different ,  ITS A ARP ATTACK, retrun FALSE
                 If it is same, ignore it (its just normal arp request), return TRUE
        '''
        # check ARP Request  packet
        self.logger.info("Received ARP Packet from dpid %s Port No %s: Opcode %d srcmac: %s dstmac %s srcip %s dstip %s", 
                         dpid, in_port, a.opcode, a.src_mac, a.dst_mac, a.src_ip, a.dst_ip)        
        # ARP REQUEST
        if not a.src_mac in self.mac_to_ip[dpid]:
            self.mac_to_ip[dpid][a.src_mac] = {"ip": a.src_ip, "port": in_port}
            self.logger.info("Added entry.....new mac ip table %s", self.mac_to_ip[dpid])
        else:
            # validate the arp entry - check is it arp posioning attack?
            if not (self.mac_to_ip[dpid][a.src_mac]["ip"] == a.src_ip and
                    self.mac_to_ip[dpid][a.src_mac]["port"] == in_port):
                self.logger.error("****** Error: ARP Poisoning attack  *** Attacker MAC %s sniffing IP %s ", a.src_mac, a.src_ip)
                self.logger.info("Existing Entry for this MAC  %s IP Address  is %s ", a.src_mac, self.mac_to_ip[dpid][a.src_mac])
                return False
        return True



    def block_port(self, datapath, portnumber):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=portnumber)
        actions = []
        self.add_flow(datapath, 101, match, actions, idle_t=300)        


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # init mac_to_ip dictionary
        self.mac_to_ip.setdefault(dpid, {})

        # init 

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        #Check whether is it arp packet, and build the intelligence (port,mac,ip) table
        #validate it.  If it is ARP Posioning , block the port.
        if  ARP_POSION_DETECTION == 1:

            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                a = pkt.get_protocol(arp.arp)
                ares =  self.arp_process(a, datapath.id, in_port)

                if ares == False and ARP_POSION_MITIGATION == 1:
                    #self.block_port(datapath.id, in_port)
                    print("Blocking the Port")
                    self.block_port(datapath, in_port)
                    return

        # checking the destination port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]  
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # we have to install IP based Match, because all ARP Packets to be handled by the application.
        if (eth.ethertype == ether_types.ETH_TYPE_IP):
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            protocol = ip.proto

            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_t=10)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle_t=10)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
