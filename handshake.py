# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.l2 import EAPOL
from scapy.layers.dot11 import RadioTap,Dot11,Dot11Beacon,Dot11ProbeReq,Dot11ProbeResp
from NA import NetworkAdapters as na
from pynput import keyboard
from myLogs import Logging
import json
from dump import wifiDump,filter
from constants import *


def write_to_file(file_name, line):
    f = open(file_name, 'a')
    f.writelines(line)
    f.close()

class Session:

    def __init__(self,Anonce=None,BSSid=None,Signal= None,Key='key1'):
        self.BSSID = BSSid
        self.signalSSI = Signal
        self.ANonce = Anonce
        self.SNonce = ''
        self.Keys = {
            'key1': False,
            'key2': False,
            'key3': False,
            'key4': False
        }
        self.Keys[Key] = True

    # Метод обнулени сессии в случае получени не соответстующего пакета-EAPOL
    def updateInfo(self,Anonce=None,BSSid=None,Signal=None,Snonce=None,newKey=None):
        self.BSSID = BSSid
        self.signalSSI = Signal
        self.ANonce = Anonce
        self.SNonce = Snonce
        for x in self.Keys.keys(): self.Keys[x] = False


class Client:

    def __init__(self,client,BSSid,ANonce,Signal,Key,pkt):
        self.auth = False
        self.clientMAC = client
        #self.BSSID = BSSid
        self.tmpSession = Session(ANonce,BSSid,Signal,Key)
        self.goodSession = {Key:pkt}

    # Метод проверки завершени сессии подключени клиента к точке доступа
    def succEAPOL(self):
        cntFalse = len([x for x in self.tmpSession.Keys.values() if x == False])
        if cntFalse == 0:
            lst = []
            for x in self.goodSession.values():
                lst.append(x)
            tmp = plist.PacketList(lst,"goodHandshake")
            wrpcap('good_eapol.cap', tmp)
            print('HANDSHAKE ready for client: {0}'.format(self.clientMAC))
            self.auth = True
            handshake.on_exit('wlan0')
            #raise KeyboardInterrupt


    #def badSessionAdd(self):
    #    bad_session = Session()
    #    bad_session.BSSID = self.tmpSession.BSSID
    #    bad_session.Keys = self.tmpSession.Keys.copy()
    #    bad_session.ANonce = self.tmpSession.ANonce
    #    self.badSession.append(bad_session)


    # Метод проверки пакета-EAPOL на соответствие текущей сессии процедуры подключени клиента
    def add_key(self,bssid=None,nonce=None,signal=None, eapKey=None, pkt=None):
        dic = {}
        dic['bssid'] = bssid
        dic['mac'] = self.clientMAC
        dic['key'] = eapKey
        write_to_file(STATES_DIR + 'handshake.state',json.dumps(dic))
        if not self.tmpSession.Keys.get(eapKey):
            if eapKey == 'key2':
                self.tmpSession.SNonce = nonce
            elif eapKey =='key3' and self.tmpSession.ANonce != nonce:
                self.tmpSession.updateInfo(None, None, None, None, None)
                self.goodSession.clear()
            print('ClientMAC: {0}, EAPOL ({1} from 4)'.format(self.clientMAC,eapKey))
            self.tmpSession.Keys[eapKey] = True
            self.goodSession[eapKey] = pkt
        else:
            if eapKey == 'key1' :
                self.tmpSession.updateInfo(nonce,bssid,signal,None,eapKey)
                self.goodSession.clear()
                self.tmpSession.Keys[eapKey] = True
                self.goodSession[eapKey] = pkt
            elif eapKey == 'key2' and self.tmpSession.Keys['key3'] == False:
                self.tmpSession.SNonce = nonce
                self.tmpSession.signalSSI = signal
                self.tmpSession.Keys[eapKey] = pkt
            elif eapKey == 'key3' and self.tmpSession.ANonce != nonce:
                self.tmpSession.updateInfo(None, None, None, None, None)
                self.goodSession.clear()
            else:
                self.tmpSession.Keys[eapKey] = pkt
        self.succEAPOL()



class handshake:
    """Handshake, осуществлет перехват пакетов на беспроводном интерфейсе. Атрибуты:
                            - iface (Интерфейс)
                            - offline (режим обработки трафика [режим реального времени/режим по pcap-файлам])
                            - store (параметр, определющий будет ли осуществлтьс запись в дамп или нет)
                            - prn (метод, который будет приментс дл обработки каждого перехваченного пакета)
                            - filter (правила фильтра)
                            - clientAP (список клиентов и точек доступа которые начали процедуру подключени)
                            """
    def __init__(self,_iface,_filter,_off = None,_store = 1):
        self.iface = _iface
        self.filter = _filter
        self.store = _store
        self.offline = _off
        self.log = Logging(LOGS_DIR + 'main.log')
        self.state = STATES_DIR + 'handshake.state'
        self.out = LOGS_DIR + 'handshake.output'
        self.clientAP = {}
        self.eapolPacket = {
            b'\x00\x8a': 'key1',
            b'\x01\n': 'key2',
            b'\x13\xca': 'key3',
            b'\x03\x0a': 'key4'
        }

    # Метод обработки, вызываемый дл каждого перехваченного пакета
    def hs(self, pkt):
        print('i-am packet')

        dic = {}

        if Dot11Beacon in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'Beacon'
            write_to_file(self.out,json.dumps(dic))

        if Dot11ProbeReq in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'ProbeRequest'
            write_to_file(self.out, json.dumps(dic))

        if Dot11ProbeResp in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'ProbeRespone'
            write_to_file(self.out, json.dumps(dic))

        if not self.test.event.is_set():
            raise KeyboardInterrupt
        if EAPOL in pkt:
            dic['src_mac'] = pkt.addr2
            dic['dst_mac'] = pkt.addr1
            dic['type'] = 'EAPOL'
            write_to_file(self.out, json.dumps(dic))
            new_pkt = pkt.getlayer(EAPOL)
            dbm_sig = pkt.getlayer(RadioTap)
            if dbm_sig is not None:
                dbm_sig = pkt.dbm_antsignal
            pkt_Dot11 = pkt.getlayer(Dot11)
            key_inform = bytes(new_pkt)[5:7]
            nonce = bytes(new_pkt)[17:22]
            try:
                tmpKey = self.eapolPacket.get(key_inform)
                if tmpKey == 'key1' or tmpKey == 'key3':
                    if pkt_Dot11.addr1 not in self.clientAP:
                        new_client = Client(pkt_Dot11.addr1, pkt_Dot11.addr2, nonce, dbm_sig, tmpKey, pkt)
                        self.clientAP[pkt_Dot11.addr1] = new_client
                        print('ClientMAC: {0}, EAPOL ({1} from 4)'.format(pkt_Dot11.addr1, tmpKey))
                        eap = {}
                        eap['bssid'] = pkt_Dot11.addr2
                        eap['mac'] = pkt_Dot11.addr1
                        eap['key'] = tmpKey
                        write_to_file(self.state,json.dumps(eap))
                    else:
                        self.clientAP[pkt_Dot11.addr1].add_key(pkt_Dot11.addr2, nonce, dbm_sig, tmpKey, pkt)
                else:
                    if pkt_Dot11.addr2 in self.clientAP:
                        self.clientAP[pkt_Dot11.addr2].add_key(pkt_Dot11.addr3, nonce, dbm_sig, tmpKey, pkt)
            except KeyError as k:
                raise ValueError('Not key: {0}'.format(k.args[0]))
            except AttributeError as attr:
                print(attr.args[0])
            print(pkt.addr1)

    # Старт перехвата пакетов-handshake
    def start(self):
        self.log.write_log('HANDSHAKE', 'Запуск сбора пакетов-handshake')
        if not self.iface is None:
            na.set_mode(self.iface, 'monitor')
            print(na.get_mode(self.iface))

        self.test = wifiDump(self.iface, self.offline, self.store)

        self.test.start(self.hs,self.filter)
        self.log.write_log('HANDSHAKE', 'Сбор пакетов-handshake завершен')

    # Завершение сбора пакетов-handshake
    @staticmethod
    def on_exit(iface):
        wifiDump.on_exit(iface)

#tmp_filter = filter.bssid('a4:2b:b0:e7:19:c0')
#tmp_filter = lambda x:x.haslayer(EAPOL)
#hdshk = handshake('wlan0',tmp_filter)
#hdshk.start()#'/home/user/PycharmProjects/wifiAttack/handshake.cap',0)

