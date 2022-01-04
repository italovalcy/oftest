"""
Amlight/AMPATH/FIU test cases

These tests check the behavior of interest for AmLight/FIU.
"""

import logging
import random

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6

class MatchTest(base_tests.SimpleDataPlane):
    """
    Base class for match tests
    """

    def verify_match(self, match, matching, nonmatching, actions=None, dp_port1=None, dp_port2=None):
        """
        Verify matching behavior

        Checks that all the packets in 'matching' match 'match', and that
        the packets in 'nonmatching' do not.

        'match' is a LOXI match object. 'matching' and 'nonmatching' are
        dicts mapping from string names (used in log messages) to string
        packet data.
        """
        in_port, out_port = openflow_ports(2)
        table_id = test_param_get("table", 0)

        logging.info("Running match test for %s", match.show())

        delete_all_flows(self.controller)

        if actions is None:
            actions=[ofp.action.output(port=out_port,
                                max_len=ofp.OFPCML_NO_BUFFER)]

        logging.info("Inserting flow sending matching packets to port %d", out_port)
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=[ofp.instruction.apply_actions(actions=actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        logging.info("Inserting match-all flow sending packets to controller")
        request = ofp.message.flow_add(
            table_id=table_id,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_CONTROLLER,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1)
        self.controller.message_send(request)

        do_barrier(self.controller)

        if dp_port1 is None:
            dp_port1 = in_port
        for name, pkt in matching.items():
            logging.info("Sending matching packet %s, expecting output to port %d", repr(name), out_port)
            pktstr = str(pkt)
            self.dataplane.send(dp_port1, pktstr)
            verify_packets(self, pktstr, [out_port])

        if dp_port2 is None:
            dp_port2 = in_port
        for name, pkt in nonmatching.items():
            logging.info("Sending non-matching packet %s, expecting packet-in", repr(name))
            pktstr = str(pkt)
            self.dataplane.send(dp_port2, pktstr)
            verify_packet_in(self, pktstr, dp_port2, ofp.OFPR_ACTION)


class NoviExpActionSetBFD(ofp.message.experimenter):
    """
    Message to configure the content of the BFD packets that the switch
    will start sending at the transmit interval negotiated with the peer
    """
    def __init__(self, port_no=0, my_disc=0, interval=0, multiplier=0, keepalive_timeout=0):
        """Build data and pass it to Ryu's OFPExperimenter message

        :param uint32 port_no: Port Number
        :param uint32 my_disc: My discriminator
        :param uint32 interval: BFD min tx and min rx interval in microseconds
        :param uint8  multiplier: BFD multiplier
        :param uint8  keepalive_timeout: Keep alive timeout flag. Value 0x00 indicates that the BFD
                                      session is deleted after 10*multiplier*negotiated_rx_interval
                                      and value 0x01 indicates infinite timeout
        """
        NOVIFLOW_EXPERIMENTER_ID = 0xff000002
        NOVIFLOW_CUSTOMER_ID = 0xff
        NOVIFLOW_ACTION_SET_BFD = 0x0004
        RESERVED = 0x00
        type_ = NOVIFLOW_CUSTOMER_ID << 24 | RESERVED << 16 | NOVIFLOW_ACTION_SET_BFD

        data = struct.pack("!HHHBB", port_no, my_disc, interval, multiplier, keepalive_timeout)
        data += struct.pack('!BBBBBB', [0,0,0,0,0,0])

        super(NoviExpActionSetBFD, self).__init__(self, experimenter=NOVIFLOW_EXPERIMENTER_ID,
							subtype=type_,
							data=data)

class BaseModifyPacketTest(base_tests.SimpleDataPlane):
    """
    Base class for action tests that modify a packet
    """

    def verify_modify(self, actions, pkt, exp_pkt):
        in_port, out_port = openflow_ports(2)

        actions = actions + [ofp.action.output(out_port)]

        match=packet_to_flow_match(self, pkt)

        logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        do_barrier(self.controller)

        logging.info("Sending packet, expecting output to port %d", out_port)
        self.dataplane.send(in_port, str(pkt))
        verify_packets(self, str(exp_pkt), [out_port])

class MatchVlanVID(MatchTest):
    """
    Match on VLAN VID
    """
    def runTest(self):
        match = ofp.match([
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|8),
        ])

        matching = {
            "vid=8": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=8),
        }

        nonmatching = {
            "vid=1": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1),
            "no vlan tag": simple_tcp_packet(),
        }

        self.verify_match(match, matching, nonmatching)

class MatchVlanVIDMasked(MatchTest):
    """
    Match on VLAN VID (masked)
    """
    def runTest(self):
        match = ofp.match([
            ofp.oxm.vlan_vid_masked(ofp.OFPVID_PRESENT|8, ofp.OFPVID_PRESENT|248),
        ])

        matching = {
            "vid=8": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=8),
            "vid=9": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=9),
            "vid=10": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=10),
            "vid=11": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=11),
            "vid=12": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=12),
            "vid=13": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=13),
            "vid=14": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=14),
            "vid=15": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=15),
        }

        nonmatching = {
            "vid=0": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=0),
            "vid=1": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1),
            "vid=2": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=2),
            "vid=4": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=4),
            "vid=16": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=4),
            "vid=17": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=4),
            "vid=18": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=4),
            "vid=19": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=4),
            "no vlan tag": simple_tcp_packet(),
        }

        self.verify_match(match, matching, nonmatching)

class MatchEthDstMasked(MatchTest):
    """
    Match on ethernet destination (masked)
    """
    def runTest(self):
        match = ofp.match([
            ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x00, 0x05],
                                   [0xff, 0xff, 0xff, 0xff, 0xf0, 0x0f])
        ])

        matching = {
            "00:01:02:03:00:05": simple_tcp_packet(eth_dst='00:01:02:03:04:05'),
            "00:01:02:03:04:15": simple_tcp_packet(eth_dst='00:01:02:03:04:15'),
            "00:01:02:03:0a:f5": simple_tcp_packet(eth_dst='00:01:02:03:0a:05'),
        }

        nonmatching = {
            "00:02:02:03:04:05": simple_tcp_packet(eth_dst='00:02:02:03:04:05'),
            "00:01:02:07:04:05": simple_tcp_packet(eth_dst='00:01:02:07:04:05'),
        }

        self.verify_match(match, matching, nonmatching)

class MatchEthDst(MatchTest):
    """
    Match on ethernet destination
    """
    def runTest(self):
        match = ofp.match([
            ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        ])

        matching = {
            "00:01:02:03:04:05": simple_tcp_packet(eth_dst='00:01:02:03:04:05'),
        }

        nonmatching = {
            "00:01:02:03:04:06": simple_tcp_packet(eth_dst='00:01:02:07:04:06'),
        }

        self.verify_match(match, matching, nonmatching)

class MatchEthType(MatchTest):
    """
    Match on ethertype
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)

        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])

        lldp_pkt = \
            scapy.Ether(dst='00:01:02:03:04:05', src='00:06:07:08:09:0a', type=0x88cc)

        matching = {
            "ipv4/tcp": simple_tcp_packet(),
            "ipv4/udp": simple_udp_packet(),
            "ipv4/icmp": simple_icmp_packet(),
            "vlan tagged": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=100),
        }

        nonmatching = {
            "arp": simple_arp_packet(),
            "lldp": lldp_pkt,
            "ipv6/tcp": simple_tcpv6_packet(),
        }

        self.verify_match(match, matching, nonmatching)

class MatchInPort(MatchTest):
    """
    Match on ingress port
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)

        match = ofp.match([
            ofp.oxm.in_port(in_port)
        ])

        matching = {
            "in_port=%d"%(in_port) : simple_tcp_packet(),
        }

        nonmatching = {
            "in_port=%d"%(out_port) : simple_tcp_packet(),
        }

        self.verify_match(match, matching, nonmatching, dp_port2=out_port)

class MatchIPv4Proto(MatchTest):
    """
    Match on ipv4 protocol field
    """
    def runTest(self):
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(6),
        ])

        matching = {
            "tcp": simple_tcp_packet(),
        }

        nonmatching = {
            "udp": simple_udp_packet(),
            "icmp": simple_icmp_packet(),
        }

        self.verify_match(match, matching, nonmatching)

class MatchLogicalPort(base_tests.SimpleDataPlane):
    """
    Match on a logical port

    This test depends on a manual setup of the logical ports and a remote switch

    on the Device Under Test:
    - set config logicalport logicalporttype lag logicalportno 1000 portno 13 14

    on the remote switch:
    - set config logicalport logicalporttype lag logicalportno 1000 portno 13 14
    - del config flow tableid all
    - set config flow tableid 0 command add priority 1000 matchfields in_port valuesmasks 1000 instruction apply_actions action output port in_port
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)
        logicalportno = 1000

        # clean up previews flows
        delete_all_flows(self.controller)

        # flow to forward to logical port
        match = ofp.match([
            ofp.oxm.in_port(logicalportno),
        ])
        actions=[ofp.action.output(port=out_port,
                            max_len=ofp.OFPCML_NO_BUFFER)]
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match,
                instructions=[ofp.instruction.apply_actions(actions=actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        # ensure all flows were installed
        do_barrier(self.controller)

        # send packets from port 1, the packet should be forwarded to logical port
        # and come back, throwing a packet in on the controller
        pkt = str(simple_icmp_packet())
        msg = ofp.message.packet_out(
            in_port=ofp.OFPP_LOCAL,
            actions=[ofp.action.output(port=logicalportno)],
            buffer_id=ofp.OFP_NO_BUFFER,
            data=pkt)
        self.controller.message_send(msg)
        verify_packets(self, pkt, [out_port])

class MatchInterestFieldsMasked(MatchTest):
    """
    Match on AmLight Interest Fields (Masked)
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)

        match = ofp.match([
            ofp.oxm.in_port(in_port),
            ofp.oxm.vlan_vid_masked(ofp.OFPVID_PRESENT|8, ofp.OFPVID_PRESENT|248),
            ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                   [0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]),
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(6),
        ])

        matching = {
            "in_port=%d vid=10 eth_dst=00:01:02:03:04:05 ipv4/tcp" % (in_port): simple_tcp_packet(dl_vlan_enable=True, vlan_vid=10, eth_dst='00:01:02:03:04:05'),
            "in_port=%d vid=11 eth_dst=00:01:02:03:04:15 ipv4/tcp" % (in_port): simple_tcp_packet(dl_vlan_enable=True, vlan_vid=11, eth_dst='00:01:02:03:04:15'),
        }

        nonmatching = {
            "ipv6/tcp": simple_tcpv6_packet(),
            "in_port=%d vid=10 eth_dst=00:01:02:03:04:05 ipv4/tcp" % (out_port): simple_tcp_packet(dl_vlan_enable=True, vlan_vid=10, eth_dst='00:01:02:03:04:05'),
            "in_port=%d vid=20 eth_dst=00:01:02:03:04:15 ipv4/tcp" % (in_port): simple_tcp_packet(dl_vlan_enable=True, vlan_vid=20, eth_dst='00:01:02:03:04:15'),
            "in_port=%d vid=11 eth_dst=00:01:02:03:04:06 ipv4/tcp" % (in_port): simple_tcp_packet(dl_vlan_enable=True, vlan_vid=10, eth_dst='00:01:02:03:04:06'),
            "in_port=%d vid=11 eth_dst=00:01:02:03:04:05 ipv4/udp" % (in_port): simple_udp_packet(dl_vlan_enable=True, vlan_vid=10, eth_dst='00:01:02:03:04:05'),
            "in_port=%d vid=11 eth_dst=00:01:02:03:04:05 ipv4/icmp" % (in_port): simple_icmp_packet(dl_vlan_enable=True, vlan_vid=10, eth_dst='00:01:02:03:04:05'),
        }

        self.verify_match(match, matching, nonmatching, dp_port2=out_port)

class ActionOutputPhyPort(MatchTest):
    """
    Output to a single port
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)

        match = ofp.match([
            ofp.oxm.in_port(in_port),
            ofp.oxm.eth_src([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x06]),
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|100),
            ofp.oxm.ipv4_src(0xc0a80001), # 192.168.0.1
            ofp.oxm.ipv4_dst(0xc0a80002), # 192.168.0.1
            ofp.oxm.ip_proto(6),
            ofp.oxm.tcp_src(1234),
            ofp.oxm.tcp_dst(80),
        ])

        matching = {
            "ipv4/tcp": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=100, eth_src='00:01:02:03:04:05', eth_dst='00:01:02:03:04:06', ip_src='192.168.0.1', ip_dst='192.168.0.2', tcp_sport=1234, tcp_dport=80),
        }

        nonmatching = {
        }

        self.verify_match(match, matching, nonmatching)

class ActionOutputController(base_tests.SimpleDataPlane):
    """
    Test packet in function for a match-all flow

    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    """
    def runTest(self):
        delete_all_flows(self.controller)

        pkt = str(simple_tcp_packet())

        request = ofp.message.flow_add(
            table_id=test_param_get("table", 0),
            cookie=42,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_CONTROLLER,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1000)

        logging.info("Inserting flow sending all packets to controller")
        self.controller.message_send(request)
        do_barrier(self.controller)

        for of_port in config["port_map"].keys():
            logging.info("PacketInWildcard test, port %d", of_port)
            self.dataplane.send(of_port, pkt)
            verify_packet_in(self, pkt, of_port, ofp.OFPR_ACTION)
            verify_packets(self, pkt, [])

class ActionOutputInPort(MatchTest):
    """
    Output to a ingress port
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)

        match = ofp.match([
            ofp.oxm.in_port(out_port),
            ofp.oxm.eth_src([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x06]),
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|100),
            ofp.oxm.ipv4_src(0xc0a80001), # 192.168.0.1
            ofp.oxm.ipv4_dst(0xc0a80002), # 192.168.0.1
            ofp.oxm.ip_proto(6),
            ofp.oxm.tcp_src(1234),
            ofp.oxm.tcp_dst(80),
        ])
        actions=[ofp.action.output(port=ofp.OFPP_IN_PORT,
                            max_len=ofp.OFPCML_NO_BUFFER)]

        matching = {
            "ipv4/tcp": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=100, eth_src='00:01:02:03:04:05', eth_dst='00:01:02:03:04:06', ip_src='192.168.0.1', ip_dst='192.168.0.2', tcp_sport=1234, tcp_dport=80),
        }

        nonmatching = {
        }

        self.verify_match(match, matching, nonmatching, actions=actions, dp_port1=out_port)

class ActionOutputLocal(base_tests.SimpleDataPlane):
    """
    Test action output LOCAL

    Send packet out message to LOCAL and check the answer as a Packet In
    """
    def runTest(self):
        delete_all_flows(self.controller)

        in_port, out_port = openflow_ports(2)

        match = ofp.match([
            ofp.oxm.in_port(in_port),
        ])

        request = ofp.message.flow_add(
            table_id=test_param_get("table", 0),
            match=match,
            cookie=42,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_LOCAL,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1000)
        logging.info("Inserting flow sending from port %d to LOCAL", in_port)
        self.controller.message_send(request)
        do_barrier(self.controller)

        sw_addr = str(self.controller.switch_addr[0])
        pkt = str(simple_arp_packet(
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      hw_tgt='ff:ff:ff:ff:ff:ff',
                      ip_snd='67.17.206.229',
                      ip_tgt='67.17.206.227',
                      arp_op = 2))

        self.dataplane.send(in_port, pkt)
        #msg = ofp.message.packet_out(
        #    in_port=ofp.OFPP_CONTROLLER,
        #    actions=[ofp.action.output(port=ofp.OFPP_LOCAL)],
        #    buffer_id=ofp.OFP_NO_BUFFER,
        #    data=pkt)

        #logging.info("PacketOut test, port LOCAL")
        #self.controller.message_send(msg)
        #verify_packets(self, pkt, [of_port])


class ActionOutputLogicalPort(MatchTest):
    """
    Output to a single port

    This test depends on a manual setup of the logical ports and a remote switch

    on the Device Under Test:
    - set config logicalport logicalporttype lag logicalportno 1000 portno 13 14
    - del stats port portno 13
    - del stats port portno 14

    on the remote switch:
    - set config logicalport logicalporttype lag logicalportno 1000 portno 13 14
    - del config flow tableid all
    - set config flow tableid 0 command add priority 1000 matchfields in_port valuesmasks 1000 instruction apply_actions action output port in_port

    after the test, check if the packets on the LAG were load balanced:
    - show stats port portno 13
    - show stats port portno 14
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)
        logicalportno = 1000

        # clean up previews flows
        delete_all_flows(self.controller)

        # flow to forward to logical port
        match = ofp.match([
            ofp.oxm.in_port(in_port),
        ])
        actions=[ofp.action.output(port=logicalportno,
                            max_len=ofp.OFPCML_NO_BUFFER)]
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match,
                instructions=[ofp.instruction.apply_actions(actions=actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        # flow to send everything else to the controller
        request = ofp.message.flow_add(
            table_id=test_param_get("table", 0),
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_CONTROLLER,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1)
        self.controller.message_send(request)

        # ensure all flows were installed
        do_barrier(self.controller)

        # send packets from port 1, the packet should be forwarded to logical port
        # and come back, throwing a packet in on the controller
        for i in range(1, 21):
            eth_src = "00:01:02:03:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255))
            eth_dst = "00:04:05:06:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255))
            ip_dst = "192.168.0.%d" % (i)
            ip_src = "192.168.0.254"
            pktstr = str(simple_icmp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src))
            self.dataplane.send(in_port, pktstr)
            verify_packet_in(self, pktstr, logicalportno, ofp.OFPR_ACTION)

class ActionOutputMultiple(base_tests.SimpleDataPlane):
    """
    Output to multiple ports

    This test depends on a manual setup of the logical ports and a remote switch

    on the Device Under Test:
    - set config logicalport logicalporttype lag logicalportno 1000 portno 13 14

    on the remote switch:
    - set config logicalport logicalporttype lag logicalportno 1000 portno 13 14
    - del config flow tableid all
    - set config flow tableid 0 command add priority 1000 matchfields in_port valuesmasks 1000 instruction apply_actions action output port in_port
    """
    def runTest(self):
        port1, port2 = openflow_ports(2)
        logicalportno = 1000

        # clean up previews flows
        delete_all_flows(self.controller)

        # flow to forward to logical port
        match = ofp.match([
            ofp.oxm.in_port(logicalportno),
        ])
        actions= [
            ofp.action.output(port=port1, max_len=ofp.OFPCML_NO_BUFFER),
            ofp.action.output(port=port2, max_len=ofp.OFPCML_NO_BUFFER),
        ]
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match,
                instructions=[ofp.instruction.apply_actions(actions=actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        # ensure all flows were installed
        do_barrier(self.controller)

        # send packets from port 1, the packet should be forwarded to logical port
        # and come back, then the packet is forwarded to port1 and port2
        pkt = str(simple_icmp_packet())
        msg = ofp.message.packet_out(
            in_port=ofp.OFPP_LOCAL,
            actions=[ofp.action.output(port=logicalportno)],
            buffer_id=ofp.OFP_NO_BUFFER,
            data=pkt)
        self.controller.message_send(msg)
        verify_packets(self, pkt, [port1, port2])

class ActionOutputTABLE(base_tests.SimpleDataPlane):
    """
    Output to TABLE special port, which submits the packet to the
    first flow table so that the packet can be processed through
    the regular OpenFlow pipeline
    """
    def runTest(self):
        port1, port2 = openflow_ports(2)

        # clean up previews flows
        delete_all_flows(self.controller)

        # flow forward to output to port1
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        actions= [
            ofp.action.output(port=port1, max_len=ofp.OFPCML_NO_BUFFER),
        ]
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match,
                instructions=[ofp.instruction.apply_actions(actions=actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        # ensure all flows were installed
        do_barrier(self.controller)

        # send packets a packet out which will be forward to first TABLE
        # and it will be processed through the regular OpenFlow pipeline
        pkt = str(simple_icmp_packet())
        msg = ofp.message.packet_out(
            in_port=ofp.OFPP_LOCAL,
            actions=[ofp.action.output(port=ofp.OFPP_TABLE)],
            buffer_id=ofp.OFP_NO_BUFFER,
            data=pkt)
        self.controller.message_send(msg)
        verify_packets(self, pkt, [port1])

class ActionDrop(base_tests.SimpleDataPlane):
    """
    Check packets whose action sets have no output actions should be dropped
    """
    def runTest(self):
        in_port, = openflow_ports(1)
        delete_all_flows(self.controller)

        # empty actions
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        actions = [
        ]
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match,
                instructions=[ofp.instruction.apply_actions(actions=actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet())
        self.dataplane.send(in_port, pkt)
        verify_no_packet_in(self, pkt, None)
        verify_packets(self, pkt, [])


class ActionPushVlanVid(BaseModifyPacketTest):
    """
    Push a vlan tag (vid=100, pcp=0)
    """
    def runTest(self):
        actions = [ofp.action.push_vlan(ethertype=0x8100),
                   ofp.action.set_field(ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|100))]
        pkt = simple_tcp_packet()
        exp_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=100, pktlen=104)
        self.verify_modify(actions, pkt, exp_pkt)

class ActionPopVlan(BaseModifyPacketTest):
    """
    Pop a vlan tag
    """
    def runTest(self):
        actions = [ofp.action.pop_vlan()]
        pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=100, pktlen=104)
        exp_pkt = simple_tcp_packet()
        self.verify_modify(actions, pkt, exp_pkt)

class ActionSetVlanVid(BaseModifyPacketTest):
    """
    Set the vlan vid
    """
    def runTest(self):
        actions = [ofp.action.set_field(ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT | 1099))]
        pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1098)
        exp_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1099)
        self.verify_modify(actions, pkt, exp_pkt)

#class SetBFD(base_tests.SimpleDataPlane):
#    """
#    Setup the BFD session
#
#    This test depends on two switches and a manual setup of the logical ports
#
#    on the two Devices Under Test:
#    - set config logicalport logicalporttype bfd logicalportno 3014 portno 14
#    - set config flow tableid 0 command add priority 1 matchfields eth_type ip_proto udp_dst valuesmasks 0x0800 17 3784 instruction apply_actions action output port local ofpff persistent
#    """
#    def runTest(self):
#        port1, port2 = openflow_ports(2)
#        logicalportno = 3014
#        actions = [NoviExpActionSetBFD(port_no=logicalportno,
#					my_disc=1,
#					interval=100000,
#					multiplier=3,
#					keepalive_timeout=1)]
#        pkt = str(simple_udp_packet(eth_src='00:00:00:00:00:01', eth_dst='00:00:00:00:00:02',
#                                        ip_src='10.0.0.1', ip_dst='10.0.0.2', udp_dport=3784))
#        # You will need to send an equivalent pkt to the 2nd switch
#        # for instance:
#        # pkt2 = str(simple_udp_packet(eth_src='00:00:00:00:00:02', eth_dst='00:00:00:00:00:01',
#        #                                ip_src='10.0.0.2', ip_dst='10.0.0.1', udp_dport=3784))
#        msg = ofp.message.packet_out(
#            in_port=ofp.OFPP_CONTROLLER,
#            actions=actions,
#            buffer_id=ofp.OFP_NO_BUFFER,
#            data=pkt)
#        self.controller.message_send(msg)
#        do_barrier(self.controller)

class TestBarrier(MatchTest):
    """
    Test Barrier request/reply
    """
    def runTest(self):
        # clean up previews flows
        delete_all_flows(self.controller)
        for i in range(100):
            match = ofp.match([
                ofp.oxm.in_port(15),
                ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|(1000+i)),
            ])
            actions= [
                ofp.action.output(port=16),
            ]
            request = ofp.message.flow_delete_strict(
                table_id=0,
                priority=1000,
                match=match)
            self.controller.message_send(request)
            do_barrier(self.controller)
            request = ofp.message.flow_add(
                    table_id=0,
                    match=match,
                    instructions=[
                        ofp.instruction.apply_actions(actions)],
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=1000)
            self.controller.message_send(request)
            #do_barrier(self.controller)
        stats = get_stats(self, ofp.message.table_stats_request())
        for entry in stats:
            if entry.table_id == 0:
                self.assertEqual(entry.active_count, 100)
                break
