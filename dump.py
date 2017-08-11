# -*- coding: utf-8 -*-

import time
import signal
import sys

from multiprocessing import Process
import threading
import os
import sys
import multiprocessing
import logging
import json
from myLogs import Logging
from scapy.all import *
from constants import *
from scapy.layers.dot11 import  Dot11,Dot11Beacon,Dot11Deauth,Dot11ProbeResp,Dot11Elt,RadioTap,EAPOL
from NA import NetworkAdapters as na

logging.basicConfig(format=u'[%(asctime)s] %(levelname)-8s  %(message)s (%(filename)s)',
                    level=LOG_LEVEL,
                    filename=LOGS_DIR + u'main.log')

class filter:

    @staticmethod
    def sport(_sport):
        fl = 'lambda x:x.getlayer(TCP).sport=={}'.format(_sport)
        return fl

    @staticmethod
    def dport(_dport):
        fl = 'lambda x:x.getlayer(TCP).dport=={}'.format(_dport)
        return fl

    @staticmethod
    def src(_sip):
        sip = 'lambda x:x.getlayer(IP).src=={}'.format(_sip)
        return sip

    @staticmethod
    def dst(_dip):
        dip = 'lambda x:x.getlayer(IP).dst=={}'.format(_dip)
        return dip

    @staticmethod
    def bssid(_bssid):
        BSSid = lambda x: Dot11 in x and x[Dot11].addr3 ==_bssid
        return BSSid

    @staticmethod
    def client_mac(_mac):
        mac = lambda x: Dot11 in x and (x[Dot11].addr2 == _mac or x[Dot11].addr1 == _mac)
        return mac


class wifiDump:
    """Дамп, осуществлет перехват пакетов на беспроводном интерфейсе. Атрибуты:
                        - iface (Интерфейс)
                        - offline (режим обработки трафика [режим реального времени/режим по pcap-файлам])
                        - store (параметр, определющий будет ли осуществлтьс запись в дамп или нет)
                        - prn (метод, который будет приментс дл обработки каждого перехваченного пакета)
                        - filter (правила фильтра)
                        """
    def __init__(self,_iface=None,_offline=None,_filter=lambda x:x.haslayer(Dot11),_store = 1):
        self.iface = _iface
        self.offline = _offline
        self.store = _store
        self.papack = None
        self.filter = _filter
        signal.signal(signal.SIGUSR1, self.read_state)
        self.state = STATES_DIR + 'dump.state'

    # Метод дл проверки изменени значени - завершени работы
    def read_state(self,signum,frame):
        self.begin_condition(self.iface)
        raise KeyboardInterrupt

    # Запуск перехвата сетевых пакетов
    def start1(self,prn,_filter):
        na.set_mode(self.iface, 'monitor')
        time.sleep(2)

        self.papack = prn
        self.my_sniff()

    def start(self,parse_packet=None,filter=lambda x:x.haslayer(Dot11)):
        p = Process(target=self.start1, args=(parse_packet, filter))
        p.start()

        run = {}
        run['pid'] = p.pid
        fl_run = open(self.state, 'w')
        fl_run.writelines(json.dumps(run))
        fl_run.close()



        #with keyboard.Listener(
        #        on_press=self.event_close,
        #        on_release=self.close_release
        #) as listen:listen.join()

    # Метод возвращающий интерфейс в начальное состоние
    @staticmethod
    def begin_condition(iface):
        subprocess.Popen(['sudo', 'iw', 'dev', iface, 'set', 'channel', '11'],
                         stdout=DN,
                         stderr=ER)
        time.sleep(0.5)
        na.set_mode(iface, 'managed')

        time.sleep(1)

    # def event_close(self,key):
    #     key_stop = key
    #     print('key_stop = {0}'.format(key_stop))
    #     if key == keyboard.Key.space:
    #         print('event_close!')
    #         self.event.clear()
    #         raise KeyboardInterrupt


    # def close_release(self,key):
    #     if key == keyboard.Key.space:
    #         print('Stop keyboard!')
    #         self.event.clear()
    #         raise KeyboardInterrupt

    # Метод дл обработки пакетов по умолчанию в случае, если пользователь не задал свой обработчик
    # def parse_packet(self,pkt):
    #     print('send_packet')
    #     if not self.event.is_set():
    #         raise KeyboardInterrupt

    def my_sniff(self):#lambda x:x.haslayer(IP)
        logging.info('Начинаетс перехват пакетов.')
        pcap = sniff(iface=self.iface, prn=self.papack, store=self.store, offline=self.offline, lfilter=self.filter)
        logging.info('Перехват пакетов завершен.')

        if len(pcap) > 0:
            wrpcap('dumps.cap', pcap)


# Завершение перехвата пакетов
def on_exit():
    tmp_fl = open(STATES_DIR + 'dump.state', 'r')
    jsn = json.load(tmp_fl)
    tmp_fl.close()
    if jsn['pid'] != None:
        os.kill(jsn['pid'], signal.SIGUSR1)
    time.sleep(5)




#interface = 'wlan0'
#na.set_mode(interface, 'monitor')
#print(na.get_mode(interface))

#fil = filter()

#my_wifi = wifiDump(_iface=interface,_filter=fil.bssid('a4:2b:b0:e7:19:c0'),_store=1)


#my_wifi.start(None)

#on_exit()

