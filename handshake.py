# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.l2 import EAPOL
from scapy.layers.dot11 import RadioTap,Dot11,Dot11Beacon,Dot11ProbeReq,Dot11ProbeResp
from NA import NetworkAdapters as na
from pynput import keyboard
import signal
from multiprocessing import Process
import logging
import json
from dump import wifiDump,filter
import dump
from constants import *


logging.basicConfig(format=u'[%(asctime)s] %(levelname)-8s  %(message)s (%(filename)s)',
                    level=LOG_LEVEL,
                    filename=LOGS_DIR + u'main.log')

def write_to_file(file_name, line):
    f = open(file_name, 'a')
    f.writelines(line)
    f.close()

class Session:
    """ Сесси, формирует дл каждого клиента информацию о стадии его подключени.
    Атрибуты:
        - Anonce (сгенерированное точкой доступа псевдослучайное число)
        - BSSID (mac точки доступа)
        - Signal (уровень сигнала до точки доступа)
        - Keys (Ключи, которые должны быть собраны в случае успешного подключени)
    """
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
    def update_info(self,Anonce=None,BSSid=None,Signal=None,Snonce=None,newKey=None):
        self.BSSID = BSSid
        self.signalSSI = Signal
        self.ANonce = Anonce
        self.SNonce = Snonce
        for x in self.Keys.keys(): self.Keys[x] = False


class Client:
    """Клиенты, дл которых провертюс подключени к конкретной точке доступа
       ### В ДАЛЬНЕЙШЕМ БУДЕТ УДАЛЕН, и будет заменен на tmpClient ###
        Атрибуты:
        - Anonce (псевдослучайное число генерируемое клиентом)
        """
    def __init__(self,client,BSSid,ANonce,Signal,Key,pkt):
        #self.auth = False
        self.clientMAC = client
        #self.BSSID = BSSid
        self.tmpSession = Session(ANonce,BSSid,Signal,Key)
        self.goodSession = {Key:pkt}

    # Метод проверки завершени сессии подключени клиента к точке доступа
    def succ_eapol(self):
        cntFalse = len([x for x in self.tmpSession.Keys.values() if x == False])
        if cntFalse == 0:
            lst = []
            for x in self.goodSession.values():
                lst.append(x)
            tmp = plist.PacketList(lst,"goodHandshake")
            wrpcap('good_eapol.cap', tmp)
            print('HANDSHAKE ready for client: {0}'.format(self.clientMAC))
            #self.auth = True
            #on_exit()
            #raise KeyboardInterrupt




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
                self.tmpSession.update_info(None, None, None, None, None)
                self.goodSession.clear()
            print('ClientMAC: {0}, EAPOL ({1} from 4)'.format(self.clientMAC,eapKey))
            self.tmpSession.Keys[eapKey] = True
            self.goodSession[eapKey] = pkt
        else:
            if eapKey == 'key1' :
                self.tmpSession.update_info(nonce,bssid,signal,None,eapKey)
                self.goodSession.clear()
                self.tmpSession.Keys[eapKey] = True
                self.goodSession[eapKey] = pkt
            elif eapKey == 'key2' and self.tmpSession.Keys['key3'] == False:
                self.tmpSession.SNonce = nonce
                self.tmpSession.signalSSI = signal
                self.tmpSession.Keys[eapKey] = pkt
            elif eapKey == 'key3' and self.tmpSession.ANonce != nonce:
                self.tmpSession.update_info(None, None, None, None, None)
                self.goodSession.clear()
            else:
                self.tmpSession.Keys[eapKey] = pkt
        self.succ_eapol()

class tmpClient:
    """ Временные клиенты, дл проверки сбора пакетов-handshake"""
    def __init__(self,_mac):
        self.mac = _mac
        self.truePack = {
            'key1': False,
            'key2': False,
            'key3': False,
            'key4': False
        }
        self.anonce1 = None
        self.anonce3 = None

    def add_nonce(self,key,nonce):
        if key == 'key1':
            self.anonce1 = nonce
        else:
            self.anonce3 = nonce

    def good_client(self):
        if self.anonce1 == self.anonce3:
            count_true = len([x for x in self.truePack.values() if x == False])
            if count_true == 0:
                return True

class Bssid:
    """Точки доступа, которые проверютс на собранный дл них handshake"""
    def __init__(self,_bssid):
        self.bssid = _bssid
        self.clients = {}

class handshake:
    """Handshake, осуществлет перехват пакетов на беспроводном интерфейсе. Атрибуты:
                            - iface (Интерфейс)
                            - offline (режим обработки трафика [режим реального времени/режим по pcap-файлам])
                            - store (параметр, определющий будет ли осуществлтьс запись в дамп или нет)
                            - prn (метод, который будет приментс дл обработки каждого перехваченного пакета)
                            - filter (правила фильтра)
                            - clientAP (список клиентов и точек доступа которые начали процедуру подключени)
                            """
    def __init__(self,_iface):
        self.iface = _iface
        self.state = STATES_DIR + 'handshake.state'
        self.out = LOGS_DIR + 'handshake.output'
        self.bssid_hs = LOGS_DIR + 'bssid_hs.output'
        self.clf_name = LOGS_DIR + 'clients.output'
        self.bssid_list = {}
        self.bssid_handshake = []
        self.clientAP = {}
        self.eapolPacket = {
            b'\x00\x8a': 'key1',
            b'\x01\n': 'key2',
            b'\x13\xca': 'key3',
            b'\x03\x0a': 'key4'
        }

    def write_to_file(self,file_name, line):
        f = open(file_name, 'a')
        f.writelines(line)
        f.close()


    # Метод обработки, вызываемый дл каждого перехваченного пакета в случае формировани
    # дампа с выполненным handshake
    def parse_handshake(self, pkt):
        dic = {}
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
            print(pkt.addr3)

    # Метод обработки, вызываемый дл каждого перехваченного пакета в случае
    # проверки дампа на наличие в нем собранного handshake
    def parse_bssid(self,pkt):

        if EAPOL in pkt:
            dot11 = pkt.getlayer(Dot11)
            new_pkt = pkt.getlayer(EAPOL)
            nonce = bytes(new_pkt)[17:22]
            key_inform = bytes(new_pkt)[5:7]
            try:
                tmpKey = self.eapolPacket.get(key_inform)
                if tmpKey == 'key1' or tmpKey == 'key3':
                    if dot11.addr3 not in self.bssid_list:
                        tmp_client = tmpClient(dot11.addr1)
                        tmp_client.truePack[tmpKey] = True
                        tmp_client.add_nonce(tmpKey,nonce)

                        tmp_bssid = Bssid(dot11.addr3)
                        tmp_bssid.clients[dot11.addr1] = tmp_client
                        self.bssid_list[dot11.addr3] = tmp_bssid
                    else:
                        if dot11.addr1 in self.bssid_list[dot11.addr3].clients:
                            self.bssid_list[dot11.addr3].clients[dot11.addr1].truePack[tmpKey] = True
                            self.bssid_list[dot11.addr3].clients[dot11.addr1].add_nonce(tmpKey,nonce)
                        else:
                            tmp_client = tmpClient(dot11.addr1)
                            tmp_client.truePack[tmpKey] = True
                            tmp_client.add_nonce(tmpKey, nonce)

                            self.bssid_list[dot11.addr3].clients[dot11.addr1] = tmp_client
                else:
                    if dot11.addr3 in self.bssid_list:
                        if dot11.addr2 in self.bssid_list[dot11.addr3].clients:
                            self.bssid_list[dot11.addr3].clients[dot11.addr2].truePack[tmpKey] = True
                            success_client = self.bssid_list[dot11.addr3].clients[dot11.addr2]
                            if success_client.good_client():
                                if dot11.addr3 not in self.bssid_handshake:
                                    self.bssid_handshake.append(dot11.addr3)
                                    self.write_to_file(self.bssid_hs,dot11.addr3)

            except KeyError as k:
                raise ValueError('Not key: {0}'.format(k.args[0]))

            except AttributeError as attr:
                print(attr.args[0])

    def file_clear(self):
        tmp_fl_out = open(self.out, 'w')
        tmp_fl_out.close()

        tmp_fl_st = open(self.state, 'w')
        tmp_fl_st.close()

        tmp_fl_bssid = open(self.bssid_hs,'w')
        tmp_fl_bssid.close()

    # Старт перехвата пакетов-handshake / собирает bssid дл , которых собран handshake
    def start_analy(self,_off=None,_filter=lambda x: x.haslayer(Dot11),_store=1):
        self.file_clear()

        logging.info('Запуск сбора пакетов-handshake')
        if not self.iface is None:
            na.set_mode(self.iface, 'monitor')


        self.test = wifiDump(self.iface, _off, _filter,_store)

        self.test.start(self.parse_bssid)
        logging.info('Сбор пакетов-handshake завершен')

    # Старт перехвата пакетов-handshake / формирование дампа с handshake
    def start_cut(self,_off = None,_filter=lambda x: x.haslayer(Dot11),_store=0):
        self.file_clear()


        logging.info('Запуск модул формировани дампа с пакетами-handshake')
        if not self.iface is None:
            na.set_mode(self.iface, 'monitor')


        self.test = wifiDump(self.iface, _off, _filter, _store)

        self.test.start(self.parse_handshake)
        logging.info('Модуль формировани дампа с пакетами-handshake завершен')


# Завершение сбора пакетов-handshake
def on_exit():
    dump.on_exit()
    time.sleep(3)


#tmp_filter = filter.bssid('a4:2b:b0:e7:19:c0')

#op = handshake('wlan0')
#op.start_analy(None,tmp_filter)

#on_exit()
