# SDN-实验1

> **计算机96   徐亮     学号：2196114661**

## 一. 实验目的

- 了解自学习交换机的工作原理，学习用 Ryu app 编程实现自学习交换机。 

- 思考环状拓扑中出现广播风暴的原因，复习传统网络怎样处理这一问题——生成树协议。

-  SDN 控制器掌握网络全局信息，思考 SDN 如何借助这一优势，以多种新策略解决环路广播问题。 

- 理解数控平面之间利用 Packet In 、 Packet Out 、 Flow Mod 等 OpenFlow Message 进行交互的 过程。 

- 学习 Flow Table 的使用，理解默认流表项的作用。

## 二. 实验环境

- **实验环境**：`VWWare Ubuntu 20.04 LTS`
- **实验工具**： `Mininet` 、  `Ryu` 、 `WireShark`等。

## 实验任务一. 自学习交换机

### 实验背景

1969年的 ARPANET 非常简单，仅由四个结点组成。假设每个结点都对应一个交换机，每个交换机都具有 一个直连主机，你的任务是实现不同主机之间的正常通信。 

预备实验中的简单交换机洪泛数据包，虽然能初步实现主机间的通信，但会带来不必要的带宽消耗；并 且会使通信内容泄露给第三者。因此，请你在简单交换机的基础上实现二层自学习交换机，避免数据包 的洪泛。

### 实验原理

在openflow中，当数据信息首次传输到交换机时，由于交换机不存在该数据信息所对应的流表，因此，会触发Packet_in消息，即交换机会将数据信息打包后，通过相应的交换机-控制器的专用通道将数据信息描述之后，传输给控制器，控制器在对数据包进行解析之后，根据相应的逻辑(基于底层网络协议)，给交换机添加相应的流表，在这之后，数据包会根据新添加的流表传输给下一个交换机或者目的地址。流程如下图所示：

![img](https://gitee.com/bright_xu/blog-image/raw/master/202204101348165.jpeg)

SDN 自学习交换机的工作流程可以理解为： 

（1）控制器为每个交换机维护一个 mac-port 映射表。 

（2）控制器收到 packet_in 消息后，解析其中携带的数据包。 

（3）控制器学习 src_mac - in_port 映射。 

（4）控制器查询 dst_mac ，如果未学习，则洪泛数据包；如果已学习，则向指定端口转发数据包 ( packet_out )，并向交换机下发流表项( flow_mod )，指导交换机转发同类型的数据包。 

### 编程思想

#### 普通交换机实现思路

在计算机网络中，交换机工作在数据链路层，交换机MAC地址表记录了同一网段中的各个主机对应交换机的端口和主机的MAC地址。当交换机接收到一个帧的时候，通过查询地址/端口对应的表（也叫站表）来确定是丢弃还是转发。如果对应的地址/端口表项为空，则采用洪泛的方法转发帧，否则就只按照指定的端口转发。

#### SDN自学习交换机实现

SDN中交换机不存储MAC表，（datapath)只存在流表。其地址学习操作由控制器（控制器中包含MAC 地址表）实现，之后控制器下发流表项给交换机。流程如下：

- 主机A向主机B发送信息，流表中只存在默认流表，告诉交换机将数据包发送给控制器。
- 控制器先进行MAC地址学习，记录主机A的MAC地址和其对应交换机端口，然后查询MAC地址表，查找主机Ｂ信息。没有则下发流表项告诉交换机先泛洪试试。
- 泛洪后，其他主机接收后丢弃数据包，不处理。主机Ｂ发现是寻找自己的，则进行消息回送，由于交换机流表中没有处理主机Ｂ到主机Ａ的信息的流表项，所以只能向控制器发送数据包。控制器先学习主机Ｂ的MAC地址和对应交换机端口，之后查询MAC地址表，找到主机A的MAC信息，下发流表项，告诉交换机如何处理主机B->主机A的消息。

#### 关键代码讲解

```python
	# 字典的样式如下
	# {'dpid':{'src':in_port, 'dst':out_port}}
	self.mac_to_port.setdefault(dpid, {})
	self.mac_to_port[dpid][src] = in_port
	
	# 转发表中存在对应关系，就按照转发表转发；否则就广播洪泛
	if dst in self.mac_to_port[dpid]:
		out_port = self.mac_to_port[dpid][dst]
	else:
		out_port = ofp.OFPP_FLOOD
        
	# 开始设置match-actions
	actions = [parser.OFPActionOutput(out_port)]
	
	# 如果执行的动作不是flood，那么此时应该依据流表项进行转发操作，所以需要添加流表到交换机
	if out_port != ofp.OFPP_FLOOD:
		match = parser.OFPMatch(in_port = in_port, eth_dst = dst)
		self.add_flow(dp, 1, match, actions)		
    # 控制器执行命令
	out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,actions=actions, data=msg.data)
	dp.send_msg(out)
```

### 实验过程

启动`mininet`生成该网络拓扑，即输入：

```shell
sudo python topo_1969_1.py
```

如下图：

![image-20220405212609245](https://gitee.com/bright_xu/blog-image/raw/master/202204052126366.png)

在编写程序实现自学习交换机后，启动控制器，即输入：

```shell
sudo ryu-manager Broadcast_Loop.py 
```

在`mininet`中输入 `UCLA ping UTAH`，可以看到ping通了，如下图：

![image-20220405213433137](https://gitee.com/bright_xu/blog-image/raw/master/202204052134194.png)

此时我们查看UCSB的抓包情况，如下图：

![image-20220405213500146](https://gitee.com/bright_xu/blog-image/raw/master/202204052135224.png)

可以看到，这与之前预备实验当中的结果不同，UCSB并没有收到数据包的洪泛，也就是没有收到UCLA 与UTAH之间通信的ICMP报文。

### 源代码

```python
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

# 新建一个类LearningSwitch
class LearningSwitch(app_manager.RyuApp):
	# 指定openflow版本为v1.3
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	def __init__(self, *args, **kwargs):
		super(LearningSwitch, self).__init__(*args, **kwargs)
		
		# maybe you need a global data structure to save the mapping
         # mac地址/端口转发表，初始化为空 
		self.mac_to_port = {}
		
	# 添加流表  
	def add_flow(self, datapath, priority, match, actions):
 		dp = datapath
 		ofp = dp.ofproto
 		parser = dp.ofproto_parser
		# 解析出actions指令
 		inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
 		mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
 		dp.send_msg(mod)  # 发送流表项
	
	# 装饰器,第一个参数表示希望接收的事件，第二个参数告诉函数在该交换机的状态下被调用
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		match = parser.OFPMatch()
		# actions=CONTROLLER:65535，ofp.OFPCML_NO_BUFFER表示设定为max_len以便接下来的封包传送
		actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
		self.add_flow(dp, 0, match, actions)
		
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		# the identity of switch
		dpid = dp.id
		# the port that receive the packet
		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		# get the mac
		dst = eth_pkt.dst
		src = eth_pkt.src
		
		# we can use the logger to print some useful information
		self.logger.info('packet: %s %s %s %s', dpid, src, dst, in_port)
		# you need to code here to avoid the direct flooding
		# having fun
 		# :)
        
		# 字典的样式如下
		# {'dpid':{'src':in_port, 'dst':out_port}}
		self.mac_to_port.setdefault(dpid, {})
		
		self.mac_to_port[dpid][src] = in_port
		
		# 转发表中存在对应关系，就按照转发表转发；否则就广播洪泛
		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofp.OFPP_FLOOD
            
		# 开始设置match-actions
		actions = [parser.OFPActionOutput(out_port)]
		
		# 如果执行的动作不是flood，那么此时应该依据流表项进行转发操作，所以需要添加流表到交换机
		if out_port != ofp.OFPP_FLOOD:
			match = parser.OFPMatch(in_port = in_port, eth_dst = dst)
			self.add_flow(dp, 1, match, actions)			
 		

		# 控制器执行命令
		out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,actions=actions, data=msg.data)
		dp.send_msg(out)
```

## 实验任务二. 环路广播

### 实验背景

UCLA 和 UCSB 通信频繁，两者间建立了一条直连链路。在新的拓扑 `topo_1969_2.py` 中运行自学习交换 机， UCLA 和 UTAH 之间无法正常通信。分析流表发现，源主机虽然只发了很少的几个数据包，但流表项 却匹配了上千次； WireShark 也截取到了数目异常大的相同报文。

下面先对环路风暴进行验证。

在建立拓扑，启动Ryu控制器以后，我使用命令`UCLA ping UCSB` 尝试让UCLA与UCSB之间进行通信，可以看到失败了：

![image-20220405221547533](https://gitee.com/bright_xu/blog-image/raw/master/202204052215584.png)

可以看到控制器在相同端口一直重复发送相同的报文：

![image-20220405221102963](https://gitee.com/bright_xu/blog-image/raw/master/202204052211040.png)

打印出流表，可以看到刘表象匹配了上万次：

![image-20220405220729558](https://gitee.com/bright_xu/blog-image/raw/master/202204052207615.png)

使用WireShark 查看UCSB端口的抓包分析，可以看到wireshark截取到了数目异常大的相同报文。

![image-20220405221659639](https://gitee.com/bright_xu/blog-image/raw/master/202204052216716.png)

这实际上是 ARP 广播数据包在环状拓扑中洪泛导致的。

### 实验原理

当序号为 dpid 的交换机从 in_port 第一次收到某个 src_mac 主机发出，询问 dst_ip 的广播 ARP Request 数据包时，控制器记录一个映射 (dpid, src_mac, dst_ip)->in_port 。下一次该交换机收到 同一 (src_mac, dst_ip) 但 in_port 不同的 ARP Request 数据包时直接丢弃，否则洪泛。

### 编程思想

#### 环路广播原因

在传统网络中，存在着一定的广播流量，占据了一部分的网络带宽。同时，在有环的拓扑中，如果不运行某些协议，广播数据还会引起网络风暴，使网络瘫痪。

#### 解决方案

当序号为 dpid 的交换机从 in_port 第一次收到某个 src_mac 主机发出，询问 dst_ip 的广播 ARP Request 数据包时，控制器记录一个映射 (dpid, src_mac, dst_ip)->in_port 。下一次该交换机收到 同一 (src_mac, dst_ip) 但 in_port 不同的 ARP Request 数据包时直接丢弃，否则洪泛。

#### 关键代码讲解

下面是check函数的定义，实现了对 ARP Request 数据包的检查。

```python
# check the in_port
# check函数实现了对 ARP Request 数据包的检查，判断是否接收过
def check(self, datapath, src, in_port):
    # 字典以dpid为键，存储转发过的的包
    self.mac_to_port.setdefault((datapath,datapath.id), {})
    # 如果数据包来源（src）在字典中有记录
    if src in self.mac_to_port[(datapath,datapath.id)]:
        # 如果in_port不是记录中的端口，说明是洪泛包，返回false
        if in_port != self.mac_to_port[(datapath,datapath.id)][src]:
            return False
	# 如果src没有记录，说明是第一次接收，加入到字典中
    else:
        self.mac_to_port[(datapath,datapath.id)][src] = in_port
        return True
```

下面是对函数check的调用，根据情况判断对数据包的操作：

```python
    # 如果目标在字典中有记录，直接设置out_port
    if dst in self.mac_to_port[(datapath,datapath.id)]:
        out_port = self.mac_to_port[(datapath,datapath.id)][dst]
    # 目标在字典中没有记录
    else:
        # 如果判断出这是后续的洪泛数据包，则不再接收
        if self.check(datapath, src, in_port) is False:
            out_port = ofproto.OFPPC_NO_RECV
        # 第一次接收，进行洪泛发送
        else:
            out_port = ofproto.OFPP_FLOOD
	# 进行对应的actions
    actions = [parser.OFPActionOutput(out_port)]
```

### 实验过程

首先使用mininet，运行拓扑文件建立拓扑：

![image-20220405221913349](https://gitee.com/bright_xu/blog-image/raw/master/202204052219407.png)

在编写完控制器程序以后，启动控制器：

![image-20220405222554699](https://gitee.com/bright_xu/blog-image/raw/master/202204052225761.png)

在mininet中查看流表，可以看到匹配次数恢复正常：

![image-20220405223956638](https://gitee.com/bright_xu/blog-image/raw/master/202204052239697.png)

输入命令 `UCLA ping UTAH`，可以看到可以ping通，如下图：

![image-20220405224126130](https://gitee.com/bright_xu/blog-image/raw/master/202204052241189.png)

在用`pingall`命令检验，可以看到所有节点之间都能ping通：

![image-20220405224203828](https://gitee.com/bright_xu/blog-image/raw/master/202204052242882.png)

### 源代码

```python
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__


class Switch_Dict(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch_Dict, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.sw = {} #(dpid, src_mac, dst_ip)=>in_port, you may use it in mission 2
        # maybe you need a global data structure to save the mapping
        # just data structure in mission 1
        

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

	# check the in_port
    def check(self, datapath, src, in_port):
        self.mac_to_port.setdefault((datapath,datapath.id), {})
        # learn a mac address to avoid FLOOD next time.
        if src in self.mac_to_port[(datapath,datapath.id)]:
            if in_port != self.mac_to_port[(datapath,datapath.id)][src]:
                return False
        else:
            self.mac_to_port[(datapath,datapath.id)][src] = in_port
            return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # the identity of switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        # the port that receive the packet
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        # get the mac
        dst = eth_pkt.dst
        src = eth_pkt.src
        # get protocols
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if dst == ETHERNET_MULTICAST and ARP in header_list:
        # you need to code here to avoid broadcast loop to finish mission 2
            if dst in self.mac_to_port[(dp,dp.id)]:
                out_port = self.mac_to_port[(dp,dp.id)][dst]
            else:
                if self.check(dp, src, in_port) is False:
                    out_port = ofp.OFPPC_NO_RECV
                else:
                    out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

        # self-learning
        # you need to code here to avoid the direct flooding 
        # having fun 
        # :)
        # just code in mission 1
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self.add_flow(dp, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(dp, 10, match, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

```



## 附加题

### 基本思想

在SDN中，我们不必拘泥于最小生成树协议来避免环路风暴带来的问题。SDN的便捷就在于他有了控制平面，高于一切交换机，我们可以用它来做一些事情。因此，这里我实现了另一种方法，也就是在控制器Ryu上建立一个ARP代理模块，用于代理恢复ARP请求，而不再向交换机发出请求。

这里利用SDN控制器可获取网络全局的信息的能力，去代理回复ARP请求，从而减少网络中泛洪的ARP请求数据。这个逻辑非常简单，也是通过自学习ARP记录，再通过查询记录并回复。

### 源代码

```python
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__


class ARP_PROXY_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARP_PROXY_13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=5, hard_timeout=15,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        header_list = dict(
            (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src  # ARP learning

        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet： %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            if self.arp_handler(header_list, datapath, in_port, msg.buffer_id):
                return None
            else:
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            hwtype = header_list[ARP].hwtype
            proto = header_list[ARP].proto
            hlen = header_list[ARP].hlen
            plen = header_list[ARP].plen
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(
                        in_port)
                    )

                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False
```

### 小思考

在SDN的解决方案当中，我们可以发现控制器是一个十分关键的角色。在上述例子中，如果交换机数量多，数据包的流量较大，控制器controller这种集中式管理可能压力就会剧增，可能吞吐量就会下降很多，甚至导致控制器崩溃。这种情况，有什么避免的办法呢。

