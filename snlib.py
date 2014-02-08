import scapy.all
import thread

# When Click the Stop Button, this will set True
# whereas Sniffer will Stop
# MAKE SURE this sets False, WHENEVER STARTS A NEW SNIFFING
Stop_Button_Click = False

# Single File re-assemble
# File content
Content = ''

# MAKE SURE to Flush the following lists, WHENEVER STARTS A NEW SNIFFING
#packet buffer ------ [[Layer,[HeaderInfos...]]..]
pktBuf = []

# packet contents
# related to pktBuf
pktCont = []


#fragmented IP packets	-----[[ID,[[offset,DataFrags]..]]..]
fragBuf = []

#protocol name  ----- ARP IP ICMP TCP UDP
Protocol = []

# type Table ---- EtherType
tabEth = ((0x0800,'IP'),(0x0806,'ARP'))

##########################################################
#get packets into the buffer
def getPkts(filterOpt,Handle,stop_filt):
	if stop_filt == None:
		scapy.all.sniff(lfilter = filterOpt,store = 0,prn = lambda x: Handle(x),stop_filter = lambda x: stop_sniff(Stop_Button_Click))
	else:
		scapy.all.sniff(lfilter = filterOpt,store = 0,prn = lambda x: Handle(x),stop_filter = lambda x: stop_filt(x)|Stop_Button_Click)


#packet pre-manipulation ----- while in getPkts()
def preHand(pkt):
	for i in tabEth:
		try:
			if pkt.type == i[0]:
				pktBuf.append([i[1],dispatch_LOW(i[1],pkt[1])])
		except AttributeError:
			pass

def dispatch_LOW(lowPtc,pkt):
	if lowPtc == 'ARP':
		pktCont.append('')
		Protocol.append('ARP')
		if pkt.op == 1:
			return ['Request','srcIP',pkt.psrc,'srcMAC',pkt.hwsrc,'dstIP',pkt.pdst,'dstMAC',pkt.hwdst]
		if pkt.op == 2:
			return ['Reply','srcIP',pkt.psrc,'srcMAC',pkt.hwsrc,'dstIP',pkt.pdst,'dstMAC',pkt.hwdst]
		return ['Broken Packet']
	if lowPtc == 'IP':
		temp = ['IPv4','srcIP',pkt.src,'dstIP',pkt.dst,'TTL',pkt.ttl,'id',pkt.id,'flags',pkt.flags]
		if pkt.flags == 2:		# DF
			if pkt.proto == 0x04:		# IPv4 Encapsulation
				temp.append([dispatch_LOW('IP',pkt[1])])
			else:
				temp.append(dispatch_HIGH(pkt.id,pkt.proto,pkt[1]))
			return temp
		elif pkt.flags == 1:		# MF
			pos = 0
			for i in fragBuf:
				if i[0] == pkt.id:
					i[1].append([pkt.frag,pkt[1]])
					i[1].sort()
					pos = 1
					break
			if pos == 0:
				fragBuf.append([pkt.id,[[pkt.frag,pkt[1]]]])
			temp.append(dispatch_HIGH(pkt.id,pkt.proto,pkt[1]))
			return temp

def dispatch_HIGH(IPv4id,hiPtc,pkt):
	#  TCP & UDP & ICMP
	if hiPtc == 0x06:	#TCP
		try:
			pktCont.append(pkt[1])
		except:
			pktCont.append('')
		Protocol.append('TCP')
		for i in fragBuf:
			if IPv4id == i[0]:
				tp = i[1][0][1]
				if tp == pkt:
					return ['TCP','sport',tp.sport,'dport',tp.dport,'seq',tp.seq,'ack',tp.ack,'dataOffset',tp.dataofs,'reserved',tp.reserved,'flags',tp.flags,'window',tp.window,'checksum',tp.chksum,'urgentPointer',tp.urgptr,'options',tp.options,'data',pkt[1]]
				else:
					return ['TCP','sport',tp.sport,'dport',tp.dport,'seq',tp.seq,'ack',tp.ack,'dataOffset',tp.dataofs,'reserved',tp.reserved,'flags',tp.flags,'window',tp.window,'checksum',tp.chksum,'urgentPointer',tp.urgptr,'options',tp.options,'data',pkt]
		try:
			pkt[1]
			return ['TCP','sport',pkt.sport,'dport',pkt.dport,'seq',pkt.seq,'ack',pkt.ack,'dataOffset',pkt.dataofs,'reserved',pkt.reserved,'flags',pkt.flags,'window',pkt.window,'checksum',pkt.chksum,'urgentPointer',pkt.urgptr,'options',pkt.options,'data',pkt[1]]
		except IndexError:
			return ['TCP','sport',pkt.sport,'dport',pkt.dport,'seq',pkt.seq,'ack',pkt.ack,'dataOffset',pkt.dataofs,'reserved',pkt.reserved,'flags',pkt.flags,'window',pkt.window,'checksum',pkt.chksum,'urgentPointer',pkt.urgptr,'options',pkt.options,'data','']
	if hiPtc == 0x11:	#UDP
		try:
			pktCont.append(pkt[1])
		except:
			pktCont.append('')
		Protocol.append('UDP')
		for i in fragBuf:
			if IPv4id == i[0]:
				tp = i[1][0][1]
				if tp == pkt:
					return ['UDP','sport',tp.sport,'dport',tp.dport,'length',tp.len,'checksum',tp.chksum,'data',pkt[1]]
				else:
					return ['UDP','sport',tp.sport,'dport',tp.dport,'length',tp.len,'checksum',tp.chksum,'data',pkt]
		try:
			pkt[1]
			return ['UDP','sport',pkt.sport,'dport',pkt.dport,'length',pkt.len,'checksum',pkt.chksum,'data',pkt[1]]
		except IndexError:
			return ['UDP','sport',pkt.sport,'dport',pkt.dport,'length',pkt.len,'checksum',pkt.chksum,'data','']
	if hiPtc == 0x01:	#ICMP
		try:
			pktCont.append(pkt[1])
		except:
			pktCont.append('')
		Protocol.append('ICMP')
		return ['ICMP','type',pkt.type,'code',pkt.code,'checksum',pkt.chksum,'id',pkt.id,'seq',pkt.seq,'originate_timestamp',pkt.ts_ori,'receive_timestamp',pkt.ts_rx,'transmit_timestamp',pkt.ts_tx,'gateway',pkt.gw,'addr_mask',pkt.addr_mask]
	else:
		Protocol.append('Others..')
		return ['Others..']

###########################################################
#save packets into file "/root/log", in the APPEND mode
def savPk():
	tmp = file('log','a')
	for i in range(len(Protocol)):
		if Protocol[i] != "Others..":
			tmp.write(str((Protocol[i],pktBuf[i])))
			tmp.write('\n')
	tmp.close()

############################################################
# reassemble IP fragments
#  takes IP id as a parameter
def pkt_assemble(IPid):
	# assemble the IP Fragments  ---- recoginized by IP fragid
	buf=''
	for i in fragBuf:
		if i[0] == IPid:
			for pkt in i[1]:
				buf += str(pkt[1])
			return [IPid,buf]
	return ['Error','Unkown ip']

###############################################################
#Basic sniffing function
def Sniff(interface = 'eth0',promisc_on = False,filt = 0,stop_filter = None):
	scapy.all.conf.sniff_promisc = promisc_on
	scapy.all.conf.iface = interface
	scapy.all.conf.ipv6_enabled = False	# No IPv6
	getPkts(filt,preHand,stop_filter)


#Threading the Sniff function to enable stop_sniff
def th_sniff(interface = 'eth0',promisc_on = False,filt = 0,stop_filter = None):
	thread.start_new_thread(Sniff,(interface,promisc_on,filt,stop_filter))

#Stop Sniff function
###### It's a Null Handler
def stop_sniff(click):
	if click:
		return True
	else:
		return False


# Specify Source & Dst-IP Sniffing	---- Considering TCP and UDP and ICMP on IPv4 Only
def src_dstIP_sniff(src,dst,iface='eth0'):
	th_sniff(iface,True,filt = lambda x: src_dstIP_filter(src,dst,x))

def src_dstIP_filter(src,dst,pkt):
	try:
		if pkt.type == 0x0800 and pkt[1].src == src and pkt[1].dst == dst:
			return True
		else:
			return False
	except:
		return False

# Specify Source & Dst-Port Sniffing	---- Considering TCP and UDP in IPv4 Only
#					---- IP Encapsulation is NOT Considered
def src_dstPort_sniff(src,pdst,iface='eth0'):
	th_sniff(iface,True,filt = lambda x: src_dstPort_filter(src,pdst,x))

def src_dstPort_filter(src,pdst,pkt):
	try:
		if pkt.type != 0x0800:
			return False
		if pkt[1].src != src:
			return False
		if pkt[1].proto != 0x11 or pkt[1].proto != 0x06:
			return False
		if pkt[2].dport == pdst:
			return True
		else:
			return False
	except:
		return False

# Specify Protocol		------- IPv4,ARP,TCP,UDP,ICMP
def pro_sniff(ptl,iface='eth0'):
	th_sniff(iface,True,filt = lambda x: pro_filter(ptl,x))

def pro_filter(ptl,pkt):
	try:
		if (ptl == 'IP' or ptl == 'IPv4') and pkt.type == 0x0800:
			return True
		if ptl == 'ARP' and  pkt.type == 0x0806:
			return True
		if ptl == 'TCP' and pkt.type == 0x0800 and pkt[1].proto == 0x06:
			return True
		if ptl == 'UDP' and pkt.type == 0x0800 and pkt[1].proto == 0x11:
			return True
		if ptl == 'ICMP' and pkt.type == 0x0800 and pkt[1].proto == 0x01:
			return True
		return False
	except:
		return False

###########################################################################
# KeyWord Search		## TODO: Different codings... Encoding? Decoding?
def search(key):
	matchPkt = []
	for ctr in range(len(Protocol)):
		if Protocol[ctr] == 'TCP' or Protocol[ctr] == 'UDP':
			if str(pktBuf[ctr]).find(key) != -1:
				matchPkt.append(pktBuf[ctr])
	return matchPkt



###############################################################################
# File Re-assemble	---- ONE tcp session, IPv4 & TCP
def single_file_asm(src,dst,psrc,iface='eth0'):
	thread.start_new_thread(sfa,(src,dst,psrc,iface))

def sfa(src,dst,psrc,iface='eth0'):
	temp = []
	Sniff(iface,True,filt = lambda x: file_filter(src,dst,psrc,temp,x),stop_filter = (lambda x: session_end(x)|Stop_Button_Click))
	for i in temp:
		try:
			Content += str(i[1])
		except IndexError:
			Content += str(i)
	

def session_end(pkt):
	try:
		pkt[1][1][1][1]
	except:
		try:
			if pkt.type == 0x0800 and pkt[1].src == src and pkt[1].dst == dst and pkt[1].proto == 0x06 and pkt[1][1].sport == psrc and pkt[1][1].flags == 1:
				print "Completed!"
				return True
			else:
				return False
		except:
			return False


def file_filter(src,dst,psrc,buf,pkt):
	try:
		pkt[1][1][1][1]
	except:
		try:
			if pkt.type == 0x0800 and pkt[1].src == src and pkt[1].dst == dst and pkt[1].proto == 0x06 and pkt[1][1].sport == psrc:
				buf.append(pkt[1][1])
				return True
			else:
				return False
		except:
			return False
