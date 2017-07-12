# -*- coding: utf-8 -*-

import time
import signal
import sys

import threading
from pynput import keyboard
from pynput.keyboard import Key,Controller
import json
from myLogs import Logging
from scapy.all import *
from constants import *
from scapy.layers.dot11 import  Dot11,Dot11Beacon,Dot11Deauth,Dot11ProbeResp,Dot11Elt,RadioTap,EAPOL
from NA import NetworkAdapters as na


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
        BSSid = lambda x: Dot11 in x and x[Dot11].addr3 == _bssid
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
    def __init__(self,_iface=None,_offline=None,_store = 1):
        self.iface = _iface
        self.offline = _offline
        self.store = _store
        self.prn = None
        self.filter = None
        self.log = Logging(LOGS_DIR + 'main.log')
        self.state = STATES_DIR + 'dump.state'

    # Метод дл проверки изменени значени - завершени работы
    def read_state(self):
        tmp_fl = open(self.state, 'r')
        jsn = json.load(tmp_fl)
        tmp_fl.close()
        if not jsn['running']:
            self.event.clear()
        time.sleep(10)

    # Запуск перехвата сетевых пакетов
    def start(self,prn,filter=lambda x:x.haslayer(Dot11)):
        run = {}
        run['running'] = True
        fl_run = open(STATES_DIR + 'dump.state', 'w')
        fl_run.writelines(json.dumps(run))
        fl_run.close()

        na.set_mode(self.iface, 'monitor')
        time.sleep(2)

        self.filter = filter
        if prn is None:
            self.prn = self.prns
        else:
            self.prn = prn
        self.event = threading.Event()
        self.event.set()
        self.t1 = threading.Thread(None, self.my_sniff)
        try:
            self.t1.start()
        except KeyboardInterrupt:
            self.event.clear()
            self.t1.join()

        while self.event.is_set():
            self.read_state()

        #with keyboard.Listener(
        #        on_press=self.event_close,
        #        on_release=self.close_release
        #) as listen:listen.join()

    # Метод возвращающий интерфейс в начальное состоние
    @staticmethod
    def begin_condition(iface):
        subprocess.Popen(['sudo', 'service', 'network-manager', 'restart'],
                         stdout=DN,
                         stderr=ER)
        time.sleep(0.5)
        subprocess.Popen(['sudo', 'iw', 'dev', iface, 'set', 'channel', '11'],
                         stdout=DN,
                         stderr=ER)
        time.sleep(0.5)
        na.set_mode(iface, 'managed')

        time.sleep(1)

    # Завершение перехвата пакетов
    def on_exit(self):
        run = {}
        run['running'] = False
        fl_run = open(STATES_DIR + 'dump.state', 'w')
        fl_run.writelines(json.dumps(run))
        fl_run.close()

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
    def prns(self,pkt):
        if not self.event.is_set():
            raise KeyboardInterrupt

    def my_sniff(self):#lambda x:x.haslayer(IP)
        self.log.write_log('DUMP', 'Начинаетс перехват пакетов.')
        pcap = sniff(iface=self.iface, prn=self.prn, store=self.store, offline=self.offline, lfilter=self.filter)
        self.log.write_log('DUMP', 'Перехват пакетов завершен.')
        if len(pcap) > 0:
            wrpcap('dumps.cap', pcap)




#interface = 'wlan0'
#na.set_mode(interface, 'monitor')
#print(na.get_mode(interface))
#
#fil = filter()
#
#my_wifi = wifiDump(_iface=interface,_store=0)
#my_wifi.start(prn=my_wifi.prns,filter=fil.bssid('a4:2b:b0:e7:19:c0'))
#print('hello')
print('Exit_dump!')
