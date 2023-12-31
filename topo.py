#-*- coding:utf-8 -*-

from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')
        s9 = self.addSwitch('s9')
        s10 = self.addSwitch('s10')
        s11 = self.addSwitch('s11')
        s12 = self.addSwitch('s12')
        s13 = self.addSwitch('s13')
        s14 = self.addSwitch('s14')
        s15 = self.addSwitch('s15')
        s16 = self.addSwitch('s16')
        s17 = self.addSwitch('s17')
        s18 = self.addSwitch('s18')

        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')

        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s2, s5)
        self.addLink(s5, s6)
        self.addLink(s6, s4)
        self.addLink(s6, s7)
        self.addLink(s6, s8)
        self.addLink(s7, s10)
        self.addLink(s8, s12)
        self.addLink(s13, s12)
        self.addLink(s13, s5)
        self.addLink(s13, s14)
        self.addLink(s14, s15)
        self.addLink(s15, s17)
        self.addLink(s17, s16)
        self.addLink(s17, s18)
        self.addLink(s18, h3)
        self.addLink(s10, s9)
        self.addLink(s9, s8)
        self.addLink(s9, s11)
        self.addLink(s11, h2)
        self.addLink(s9, h4)

topos = {'mytopo': ( lambda: MyTopo() )}
