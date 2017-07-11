from scapy.all import *
from scapy.layers.l2 import EAPOL
from scapy.layers.dot11 import Dot11ProbeResp,Dot11,Dot11Beacon,Dot11ProbeReq,Dot11Elt
import threading
import json
from logging import Logging
from constants import *
from location import Location
from clientAndHotspot import Client,Hotspot
from NA import NetworkAdapters as na


class client:
    """Клиент, находщийс в зоне действи сигнала адаптера. Атрибуты:
            - mac
            - signal"""
    def __init__(self,mac):
        self._mac = mac
        self.signal = None

class accsessPoint:
    """Точка доступа, находщийс в зоне действи сигнала адаптера. Атрибуты:
                - bssid (mac точки доступа)
                - signal (Уровень сигнала)
                - model роутера
                - essid (им точки доступа)
                - channel (канал на котором работает точка доступа)"""
    def __init__(self,bssid):
        self.BSSid = bssid
        self.model = None
        self.ap_signal = None
        self.ESSid = None
        self.ap_channel = None

class monitor:
    """Мониторинг, исследует беспроводную среду на наличие активных точек доступа и клиентов. Атрибуты:
                    - clnt (клиенты)
                    - ap (точки доступа)
                    - iface (интерфейс на котором слушаем среду)"""
    def __init__(self,_iface):
        self.clnt = {}
        self.ap = {}
        self.iface = _iface
        self.log = Logging(LOGS_DIR_NAME + 'main.log')
        self.apf = open(LOGS_DIR_NAME + 'networks.output', 'w')
        self.clf = open(LOGS_DIR_NAME + 'clients.output', 'w')
        self.cord = Location()

    #Метод добавлени информации о точке доступа в БД
    @staticmethod
    def insert_ap_db(ap,cord):
        params = json.loads(cord)
        ap_db = Hotspot(ap['bssid'],ap['essid'],ap['signal'],params['lat'],params['lon'])#add signal
        ap_db.insert_info()

    #Метод вставки информации о клиенте в БД
    @staticmethod
    def insert_cln_db(mac,signal,locat):
        cln_db = Client(mac,signal,None,None,None)
        cln_db.insert_info()
        cln_db.insert_geolocation(mac,signal,locat)


    #Модул извлечени информации о точке доступа из пакетов Beacon
    def addAP(self,pkt):
        dic = {}
        jsn = self.cord.get_current_loc(2)
        if pkt.addr2 not in self.ap:
            pktDot11Elt = pkt.getlayer(Dot11Elt)
            ap_tmp = accsessPoint(pkt.addr2)
            dic['bssid'] = pkt.addr2

            try:
                dic['essid'] = pktDot11Elt.info.decode('utf-8')
            except UnicodeDecodeError:
                dic['essid'] = 'none'
            for rg in range(1,2):
                pktDot11Elt = pktDot11Elt.payload
            chn = bytes(pktDot11Elt.payload)[2:3]
            dic['power'] = pkt.dbm_antsignal
            dic['channel'] = int.from_bytes(chn, 'big')
            self.apf.writelines(json.dumps(dic))
            self.insert_ap_db(dic,jsn)
            #apf.close()
            ap_tmp.ap_signal = pkt.dbm_antsignal
            self.ap[pkt.addr2] = ap_tmp
        else:
            if self.ap[pkt.addr2].ap_signal < pkt.dbm_antsignal:
                self.ap[pkt.addr2].ap_signal = pkt.dbm_antsignal
                pktDot11Elt = pkt.getlayer(Dot11Elt)
                try:
                    dic['essid'] = pktDot11Elt.info.decode('utf-8')
                except UnicodeDecodeError:
                    dic['essid'] = 'none'
                dic['bssid'] = pkt.addr2
                dic['power'] = pkt.dbm_antsignal
                for rg in range(1, 2):
                    pktDot11Elt = pktDot11Elt.payload
                chn = bytes(pktDot11Elt.payload)[2:3]
                dic['channel'] = int.from_bytes(chn, 'big')
                self.insert_ap_db(dic, jsn)
        #ap.close()

    #Метод извлечени информации о точке доступа и о клиенте из пакетов ProbeResponse
    def fromResp(self,pkt):
        #tmp_patt = r'[a-zA-Z-]{5,9}'
        dic_ap = {}
        dic_cl = {}
        pktDot11Elt = pkt.getlayer(Dot11Elt)
        #model = pkt.getlayer(Dot11Elt)
        for rg in range(1, 2):
            pktDot11Elt = pktDot11Elt.payload
        tmp_bytes = bytes(pktDot11Elt.payload)[2:3]
        jsn = self.cord.get_current_loc(2)
        if pkt.addr2 not in self.ap:
            ap_tmp = accsessPoint(pkt.addr2)
            bt = tmp_bytes
            ap_tmp.ap_signal = pkt.dbm_antsignal
            dic_ap['bssid'] = pkt.addr2
            try:
                dic_ap['essid'] = pktDot11Elt.info.decode('utf-8')
            except UnicodeDecodeError:
                dic_ap['essid'] = 'none'
            dic_ap['power'] = pkt.dbm_antsignal
            dic_ap['channel'] = int.from_bytes(bt, 'big')
            self.apf.writelines(json.dumps(dic_ap))
            self.insert_ap_db(dic_ap,jsn)
            self.ap[pkt.addr2] = ap_tmp
        else:
            if self.ap[pkt.addr2].ap_signal < pkt.dbm_antsignal:
                self.ap[pkt.addr2].ap_signal = pkt.dbm_antsignal
                tmp_bytes = bytes(pktDot11Elt.payload)[2:3]
                bt = tmp_bytes
                dic_ap['bssid'] = pkt.addr2
                try:
                    dic_ap['essid'] = pktDot11Elt.info.decode('utf-8')
                except UnicodeDecodeError:
                    dic_ap['essid'] = 'none'
                dic_ap['power'] = pkt.dbm_antsignal
                dic_ap['channel'] = int.from_bytes(bt, 'big')
                self.apf.writelines(json.dumps(dic_ap))
                self.insert_ap_db(dic_ap, jsn)

        if pkt.addr1 not in self.clnt:
            #cl = open(LOGS_DIR_NAME + 'clients.output', 'a')
            dic_cl['mac'] = pkt.addr2
            dic_cl['power'] = pkt.dbm_antsignal
            self.clf.writelines(json.dumps(dic_cl))
            self.insert_cln_db(pkt.addr2,pkt.dbm_antsignal,jsn)
            #cl.close()

            clnt_tmp = client(pkt.addr1)
            clnt_tmp.signal = pkt.dbm_antsignal
            self.clnt[pkt.addr1] = clnt_tmp
        else:
            if self.clnt[pkt.addr1].signal < pkt.dbm_antsignal:
                self.clnt[pkt.addr1].signal = pkt.dbm_antsignal
                dic_cl['mac'] = pkt.addr2
                dic_cl['power'] = pkt.dbm_antsignal
                self.insert_cln_db(pkt.addr2, pkt.dbm_antsignal, jsn)
                self.clf.writelines(json.dumps(dic_cl))


    # Метод извлечени информации  и о клиенте из пакетов ProbeRequest
    def addClient(self,pkt):
        #cl = open(LOGS_DIR_NAME + 'clients.output','a')
        dic = {}
        jsn = self.cord.get_current_loc(2)
        if pkt.addr2 not in self.clnt:
            dic['mac'] = pkt.addr2
            dic['power'] = pkt.dbm_antsignal
            self.clf.writelines(json.dumps(dic))
            self.insert_cln_db(pkt.addr2,pkt.dbm_antsignal,jsn)

            clnt_tmp = client(pkt.addr2)
            clnt_tmp.signal = pkt.dbm_antsignal
            self.clnt[pkt.addr2] = clnt_tmp
        else:
            if self.clnt[pkt.addr2].signal < pkt.dbm_antsignal:
                self.clnt[pkt.addr2].signal = pkt.dbm_antsignal
                dic['mac'] = pkt.addr2
                dic['power'] = pkt.dbm_antsignal
                self.clf.writelines(json.dumps(dic))
                self.insert_cln_db(pkt.addr2, pkt.dbm_antsignal, jsn)
        #cl.close()

    #Смена канала на беспроводном адаптере
    def set_channel(self):
        for chn in range(1, 12):
            self.log.write_log('MONITORING','Анализ беспроводной сети на канале: {}.'.format(chn))
            chnl = str(chn)
            subprocess.Popen(['sudo','iw','dev', self.iface,'set','channel',chnl],
                                 stdout=DN,
                                 stderr=ER)
            time.sleep(1)

            if not self.event.is_set():
                break
            time.sleep(2)

    #Старт мониторинга беспровдоной сети
    def start(self,offline=None,store=0):
        self.log.write_log('MONITORING','Запущен мониторинг беспроводной сети.')
        interface = self.iface
        na.set_mode(interface, 'monitor')
        time.sleep(2)

        self.event = threading.Event()
        self.event.set()
        self.t1 = threading.Thread(None, self.my_sniff)
        try:
            self.t1.start()
        except KeyboardInterrupt:
            self.event.clear()
            self.t1.join()

        while self.event.is_set():
            self.set_channel()


    #Метод перехвата пакетов на уровне Dot11
    def my_sniff(self):  # lambda x:x.haslayer(IP)
        try:
            pcap = sniff(iface=self.iface, prn=self.prn, store=1, lfilter=lambda x: x.haslayer(Dot11))
            self.log.write_log('MONITORING', 'Мониторинг беспроводной сети завершен.')
            self.apf.close()
            self.clf.close()
            if len(pcap) > 0:
                wrpcap('dumps.cap', pcap)
        except KeyboardInterrupt:
            self.log.write_log('MONITORING_KEYBOARD', 'Мониторинг беспроводной сети завершен.')

    #Метод обработки, вызываемый дл каждого перехваченного пакета
    def prn(self,pkt):
        print('i-am packet')
        if not self.event.is_set():
            raise KeyboardInterrupt

        if Dot11Beacon in pkt:
            self.addAP(pkt)

        if Dot11ProbeReq in pkt:
            self.addClient(pkt)

        if Dot11ProbeResp in pkt:
            self.fromResp(pkt)

    #Возвращает первоначальное состоние сетевого интерфейса
    def begin_condition(self):
        subprocess.Popen(['sudo', 'iw', 'dev', self.iface, 'set', 'channel', '11'],
                         stdout=DN,
                         stderr=ER)
        time.sleep(0.5)
        na.set_mode(self.iface, 'managed')
        time.sleep(0.5)
        subprocess.Popen(['sudo', 'service', 'network-manager','restart'],
                         stdout=DN,
                         stderr=ER)
        time.sleep(0.5)
        na.set_mode(self.iface, 'managed')
        time.sleep(1)

    def on_exit(self):
        self.event.clear()


#mon = monitor('wlan0')
#mon.start('/home/user/PycharmProjects/wifiAttack/dumps.cap',0)
#mon.begin_condition()


