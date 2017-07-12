from scapy.all import *
from scapy.layers.l2 import EAPOL
from scapy.layers.dot11 import Dot11ProbeResp, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt
import threading
import json
from myLogs import Logging
from dump import wifiDump as wd
from constants import *
from location import Location
from clientAndHotspot import Client, Hotspot
from NA import NetworkAdapters as na


class client:
    """Клиент, находщийс в зоне действи сигнала адаптера. Атрибуты:
            - mac
            - signal"""

    def __init__(self, mac):
        self._mac = mac
        self.signal = None


class accsessPoint:
    """Точка доступа, находщийс в зоне действи сигнала адаптера. Атрибуты:
                - bssid (mac точки доступа)
                - signal (Уровень сигнала)
                - model роутера
                - essid (им точки доступа)
                - channel (канал на котором работает точка доступа)"""

    def __init__(self, bssid):
        self.BSSid = bssid
        self.model = None
        self.ap_signal = None
        self.ESSid = None
        self.ap_channel = None


def write_to_file(file_name, line):
    f = open(file_name, 'a')
    f.writelines(line)
    f.close()

#on_off = True

class Monitor:
    """Мониторинг, исследует беспроводную среду на наличие активных точек доступа и клиентов. Атрибуты:
                    - clnt (клиенты)
                    - ap (точки доступа)
                    - iface (интерфейс на котором слушаем среду)"""
    on_off = True

    def __init__(self, _iface):
        self.clnt = {}
        self.ap = {}
        self.iface = _iface
        self.log = Logging(LOGS_DIR + 'main.log')
        self.apf_name = LOGS_DIR + 'networks.output'
        self.clf_name = LOGS_DIR + 'clients.output'
        self.state = STATES_DIR + 'monitoring.state'
        self.out = LOGS_DIR + 'monitoring.output'
        self.cord = Location()

    # Метод добавлени информации о точке доступа в БД
    @staticmethod
    def insert_ap_db(ap, cord):
        ap_db = Hotspot(bssid=ap['bssid'], essid=ap['essid'],
                        pwr=ap['power'], latitude=cord['lat'],
                        longitude=cord['lon'])
        ap_db.insert_info()

    # Метод вставки информации о клиенте в БД
    @staticmethod
    def insert_cln_db(mac, signal, locat):
        cln_db = Client(mac=mac, pwr=signal,
                        cur_ip=None, nick=None)
        cln_db.insert_info()
        Client.insert_geolocation(mac, signal, str(locat).replace("'", '"'))

    # Модул извлечени информации о точке доступа из пакетов Beacon
    def add_ap(self, pkt):
        dic = {}
        #jsn = self.cord.get_current_loc(2)
        if pkt.addr2 not in self.ap:
            pktDot11Elt = pkt.getlayer(Dot11Elt)
            ap_tmp = accsessPoint(pkt.addr2)
            dic['bssid'] = pkt.addr2

            try:
                dic['essid'] = pktDot11Elt.info.decode('utf-8')
            except UnicodeDecodeError:
                dic['essid'] = 'noname'
            for rg in range(1, 2):
                pktDot11Elt = pktDot11Elt.payload
            chn = bytes(pktDot11Elt.payload)[2:3]
            dic['power'] = pkt.dbm_antsignal
            dic['channel'] = int.from_bytes(chn, 'big')
            write_to_file(self.apf_name, json.dumps(dic))
            #self.insert_ap_db(dic, jsn)
            ap_tmp.ap_signal = pkt.dbm_antsignal
            self.ap[pkt.addr2] = ap_tmp
        else:
            if self.ap[pkt.addr2].ap_signal < pkt.dbm_antsignal:
                self.ap[pkt.addr2].ap_signal = pkt.dbm_antsignal
                pktDot11Elt = pkt.getlayer(Dot11Elt)
                try:
                    dic['essid'] = pktDot11Elt.info.decode('utf-8')
                except UnicodeDecodeError:
                    dic['essid'] = 'noname'
                dic['bssid'] = pkt.addr2
                dic['power'] = pkt.dbm_antsignal
                for rg in range(1, 2):
                    pktDot11Elt = pktDot11Elt.payload
                chn = bytes(pktDot11Elt.payload)[2:3]
                dic['channel'] = int.from_bytes(chn, 'big')
                #self.insert_ap_db(dic, jsn)


    # Метод извлечени информации о точке доступа и о клиенте из пакетов ProbeResponse
    def from_resp(self, pkt):
        # tmp_patt = r'[a-zA-Z-]{5,9}'
        dic_ap = {}
        dic_cl = {}
        pktDot11Elt = pkt.getlayer(Dot11Elt)
        # model = pkt.getlayer(Dot11Elt)
        for rg in range(1, 2):
            pktDot11Elt = pktDot11Elt.payload
        tmp_bytes = bytes(pktDot11Elt.payload)[2:3]
        #jsn = self.cord.get_current_loc(2)
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
            write_to_file(self.apf_name, json.dumps(dic_ap))
            #self.insert_ap_db(dic_ap, jsn)
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
                write_to_file(self.apf_name, json.dumps(dic_ap))
                #self.insert_ap_db(dic_ap, jsn)

        if pkt.addr1 not in self.clnt:
            dic_cl['mac'] = pkt.addr1
            dic_cl['power'] = pkt.dbm_antsignal
            write_to_file(self.clf_name, json.dumps(dic_cl))
            #self.insert_cln_db(pkt.addr2, pkt.dbm_antsignal, jsn)

            clnt_tmp = client(pkt.addr1)
            clnt_tmp.signal = pkt.dbm_antsignal
            self.clnt[pkt.addr1] = clnt_tmp
        else:
            if self.clnt[pkt.addr1].signal < pkt.dbm_antsignal:
                self.clnt[pkt.addr1].signal = pkt.dbm_antsignal
                dic_cl['mac'] = pkt.addr2
                dic_cl['power'] = pkt.dbm_antsignal
                #self.insert_cln_db(pkt.addr2, pkt.dbm_antsignal, jsn)

    # Метод извлечени информации  и о клиенте из пакетов ProbeRequest
    def add_сlient(self, pkt):
        # cl = open(LOGS_DIR_NAME + 'clients.output','a')
        dic = {}
        #jsn = self.cord.get_current_loc(2)
        if pkt.addr2 not in self.clnt:
            dic['mac'] = pkt.addr2
            dic['power'] = pkt.dbm_antsignal
            write_to_file(self.clf_name, json.dumps(dic))
            #self.insert_cln_db(pkt.addr2, pkt.dbm_antsignal, jsn)

            clnt_tmp = client(pkt.addr2)
            clnt_tmp.signal = pkt.dbm_antsignal
            self.clnt[pkt.addr2] = clnt_tmp
        else:
            if self.clnt[pkt.addr2].signal < pkt.dbm_antsignal:
                self.clnt[pkt.addr2].signal = pkt.dbm_antsignal
                dic['mac'] = pkt.addr2
                dic['power'] = pkt.dbm_antsignal
                #self.insert_cln_db(pkt.addr2, pkt.dbm_antsignal, jsn)

    # Смена канала на беспроводном адаптере
    def set_channel(self):
        for chn in range(1, 12):
            self.log.write_log('MONITORING', 'Анализ беспроводной сети на канале: {}.'.format(chn))
            chnl = str(chn)
            subprocess.Popen(['sudo', 'iw', 'dev', self.iface, 'set', 'channel', chnl],
                             stdout=DN,
                             stderr=ER)
            time.sleep(1)

            tmp_fl = open(self.state,'r')
            jsn = json.load(tmp_fl)
            tmp_fl.close()
            if not jsn['running']:
                self.event.clear()
                break
            time.sleep(2)

        self.on_exit()#удалить при использовании ручного вызова on_exit()

    def init_file(self):
        tmp_fl_cl = open(self.clf_name, 'w')
        tmp_fl_cl.close()
        tmp_fl_ap = open(self.apf_name, 'w')
        tmp_fl_ap.close()
        tmp_fl_out = open(self.out,'w')
        tmp_fl_out.close()


    # Старт мониторинга беспровдоной сети
    def start(self, offline=None, store=1):
        run = {}
        run['running'] = True
        fl_run = open(self.state,'w')
        fl_run.writelines(json.dumps(run))
        fl_run.close()
        #on_off = True
        self.log.write_log('MONITORING', 'Запущен мониторинг эфира')
        interface = self.iface
        self.init_file()
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


        wd.begin_condition(self.iface)

    # Метод перехвата пакетов на уровне Dot11
    def my_sniff(self):  # lambda x:x.haslayer(IP)
        try:
            self.log.write_log('MONITORING', 'Начинаетс перехват пакетов.')
            pcap = sniff(iface=self.iface, prn=self.prn, store=1, lfilter=lambda x: x.haslayer(Dot11))
            self.log.write_log('MONITORING', 'Мониторинг эфира завершен.')
            if len(pcap) > 0:
                wrpcap('dumps.cap', pcap)
        except KeyboardInterrupt:
            self.log.write_log('MONITORING_KEYBOARD', 'Мониторинг эфира завершен.')

    # Метод обработки, вызываемый дл каждого перехваченного пакета
    def prn(self, pkt):
        # print('i-am packet')
        if not self.event.is_set():
            raise KeyboardInterrupt

        dic = {}

        if Dot11Beacon in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'Beacon'
            write_to_file(self.out,json.dumps(dic))
            self.add_ap(pkt)


        if Dot11ProbeReq in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'ProbeRequest'
            write_to_file(self.out, json.dumps(dic))
            self.add_сlient(pkt)

        if Dot11ProbeResp in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'ProbeRespone'
            write_to_file(self.out, json.dumps(dic))
            self.from_resp(pkt)

    # Возвращает первоначальное состоние сетевого интерфейса


    @staticmethod
    def on_exit():
        run = {}
        run['running'] = False
        fl_run = open(STATES_DIR + 'monitoring.state', 'w')
        fl_run.writelines(json.dumps(run))
        fl_run.close()


#mon = Monitor('wlan0')
#mon.start(None,1)

#print('exit')
