package main

// Advertise network services via multicast DNS

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	ipv4mcastaddr = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}

	ipv6mcastaddr = &net.UDPAddr{
		IP:   net.ParseIP("ff02::fb"),
		Port: 5353,
	}
)

type packetConn interface {
	ReadFrom(b []byte) (n, ifIndex int, src *net.UDPAddr, err error)
	WriteTo(b []byte, ifIndex int, addr *net.UDPAddr) (int, error)
}

type v4PacketConn struct {
	*ipv4.PacketConn
	*net.Interface
}

func (v4pc *v4PacketConn) ReadFrom(b []byte) (n, ifIndex int, src *net.UDPAddr, err error) {
	n, cm, s, err := v4pc.PacketConn.ReadFrom(b)
	if err == nil {
		ifIndex = cm.IfIndex
	}
	return n, ifIndex, s.(*net.UDPAddr), err
}

func (v4pc *v4PacketConn) WriteTo(b []byte, ifIndex int, dst *net.UDPAddr) (n int, err error) {
	return v4pc.PacketConn.WriteTo(b, &ipv4.ControlMessage{IfIndex: ifIndex}, dst)
}

type v6PacketConn struct {
	*ipv6.PacketConn
	*net.Interface
}

func (v6pc *v6PacketConn) ReadFrom(b []byte) (n, ifIndex int, src *net.UDPAddr, err error) {
	n, cm, s, err := v6pc.PacketConn.ReadFrom(b)
	if err == nil {
		ifIndex = cm.IfIndex
	}
	return n, ifIndex, s.(*net.UDPAddr), err
}

func (v6pc *v6PacketConn) WriteTo(b []byte, ifIndex int, dst *net.UDPAddr) (n int, err error) {
	return v6pc.PacketConn.WriteTo(b, &ipv6.ControlMessage{IfIndex: ifIndex}, dst)
}

type Proxy struct {
	forward chan pkt
	zones   []*zone
}

func New() *Proxy {
	return &Proxy{forward: make(chan pkt)}
}

func (proxy *Proxy) Run() {
	log.Printf("Listening...")
	for {
		p := <-proxy.forward
		go func(p pkt) {
			for _, zone := range proxy.zones {
				if p.src != zone && p.isV4() == zone.isV4() {
					zone.forward(p)
				}
			}
		}(p)
	}
}

func (p *Proxy) AddInterface(iface *net.Interface, options ...ZoneOption) error {
	z, _ := newZone(p.forward, options...)
	p.zones = append(p.zones, z)
	err := z.listen(*iface, ipv4mcastaddr)
	if err == nil {
		z, _ = newZone(p.forward, options...)
		p.zones = append(p.zones, z)
		err = z.listen(*iface, ipv6mcastaddr)
	}
	return err
}

type zone struct {
	*net.UDPAddr
	packetConn
	iface net.Interface

	upstream chan<- pkt
	deliver  chan pkt

	forwardQuestion bool
	forwardAnswer   bool

	fixA   func(*dns.A)
	fixPtr func(*dns.PTR)
	fixSrv func(*dns.SRV)
}

type ZoneOption func(*zone) error

func ForwardQuestions() ZoneOption {
	return func(z *zone) error {
		z.forwardQuestion = true
		return nil
	}
}

func ForwardAnswers() ZoneOption {
	return func(z *zone) error {
		z.forwardAnswer = true
		return nil
	}
}

func FixAddress(addr string) ZoneOption {
	return func(z *zone) error {
		ip := net.ParseIP(addr)
		if ip != nil {
			z.fixA = func(a *dns.A) {
				a.A = ip
			}
			return nil
		}
		return fmt.Errorf("Invalid address format %q", addr)
	}
}

func FixPtr(ptr string) ZoneOption {
	return func(z *zone) error {
		z.fixPtr = func(p *dns.PTR) {
			p.Ptr = ptr
		}
		return nil
	}
}

func newZone(upstream chan<- pkt, options ...ZoneOption) (z *zone, err error) {
	z = &zone{
		deliver:  make(chan pkt),
		upstream: upstream,

		fixA:   func(*dns.A) {},
		fixPtr: func(*dns.PTR) {},
		fixSrv: func(*dns.SRV) {},
	}

	for _, option := range options {
		err = option(z)
		if err != nil {
			break
		}
	}
	return z, err
}

func (z *zone) listen(iface net.Interface, addr *net.UDPAddr) error {
	log.Printf("Listening on %s:%s", iface.Name, addr.String())
	z.iface = iface
	conn, err := openSocket(&iface, addr)
	if err != nil {
		return err
	}

	z.UDPAddr = addr
	z.packetConn = conn
	go z.mainloop()
	return nil
}

func setSockOpt(conn *net.UDPConn) error {
	f, err := conn.File()
	if err == nil {
		err = syscall.SetsockoptInt(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}
	return err
}

func openSocket(iface *net.Interface, addr *net.UDPAddr) (packetConn, error) {
	switch addr.IP.To4() {
	case nil:
		conn, err := net.ListenMulticastUDP("udp6", iface, ipv6mcastaddr)
		if err == nil {
			err = setSockOpt(conn)
			if err == nil {
				pc := &v6PacketConn{ipv6.NewPacketConn(conn), iface}
				err = pc.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
				if err == nil {
					err = pc.SetMulticastLoopback(false)
				}
				return pc, err
			}
		}
		return nil, err
	default:
		conn, err := net.ListenMulticastUDP("udp4", iface, ipv4mcastaddr)
		if err == nil {
			err = setSockOpt(conn)
			if err == nil {
				pc := &v4PacketConn{ipv4.NewPacketConn(conn), iface}
				err = pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
				if err == nil {
					err = pc.SetMulticastLoopback(false)
				}
				return pc, err
			}
		}
		return nil, err
	}
	panic("unreachable")
}

type pkt struct {
	*dns.Msg
	*net.UDPAddr
	ifIndex int
	src     *zone
}

func (p *pkt) isV4() bool {
	if p.UDPAddr.IP.To4() == nil {
		return false
	}
	return true
}

func (z *zone) isV4() bool {
	if z.UDPAddr.IP.To4() == nil {
		return false
	}
	return true
}

func (z *zone) readloop(in chan pkt) {
	var addrs []*net.IPNet
	a, err := z.iface.Addrs()
	if err != nil {
		log.Printf("Failed to lookup addresses for %s", z.iface.Name)
	} else {
		for _, addr := range a {
			addrs = append(addrs, addr.(*net.IPNet))
		}
	}

	/*self := func(ip net.IP) bool {
		for _, addr := range addrs {
			log.Printf("Comparing %s to %s", ip.String(), addr.IP.String())
			if ip.Equal(addr.IP) {
				return true
			}
		}
		return false
	}*/

	martian := func(ip net.IP) bool {
		for _, net := range addrs {
			//log.Printf("Comparing %s to %s", ip.String(), net.String())
			if net.Contains(ip) {
				return false
			}
		}
		return true
	}

	for {
		msg, addr, ifIndex, err := z.readMessage()
		if err != nil {
			// log dud packets
			log.Printf("Could not read from %v: %s", z.packetConn, err)
			continue
		} else if ifIndex != z.iface.Index || martian(addr.IP) {
			continue
		}
		log.Printf("Read from %s: %s -> %s", z.iface.Name, addr.IP, z.UDPAddr.IP)
		in <- pkt{msg, addr, ifIndex, z}
	}
}

func (z *zone) fixAnswer(msg *dns.Msg) {
	for _, answer := range msg.Answer {
		switch t := answer.(type) {
		case *dns.A:
			z.fixA(t)
		case *dns.PTR:
			z.fixPtr(t)
		case *dns.SRV:
			z.fixSrv(t)
		}
	}
}

func (z *zone) forward(p pkt) {
	z.deliver <- p
}

func (z *zone) mainloop() {
	in := make(chan pkt, 32)
	go z.readloop(in)
	for {
		select {
		case pkt := <-in:
			shouldForward := len(pkt.Msg.Question) > 0 && z.forwardQuestion

			if len(pkt.Msg.Answer) > 0 && z.forwardAnswer {
				shouldForward = true
				z.fixAnswer(pkt.Msg)
			}

			if shouldForward {
				z.upstream <- pkt
			}
		case pkt := <-z.deliver:
			if pkt.ifIndex != z.iface.Index {
				err := z.writeMessage(pkt.Msg, z.UDPAddr)
				if err != nil {
					log.Printf("Failed to write packet: %v", err)
				}
			}
		}
	}
}

// encode an mdns msg and broadcast it on the wire
func (z *zone) writeMessage(msg *dns.Msg, addr *net.UDPAddr) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	log.Printf("Writing to %s", z.iface.Name)
	_, err = z.WriteTo(buf, z.iface.Index, addr)
	return err
}

// consume an mdns packet from the wire and decode it
func (z *zone) readMessage() (*dns.Msg, *net.UDPAddr, int, error) {
	buf := make([]byte, 1500)

	read, ifIndex, uaddr, err := z.ReadFrom(buf)
	if err != nil {
		log.Printf("Error reading: %v", err)
		return nil, nil, ifIndex, err
	}

	var msg dns.Msg
	if err := msg.Unpack(buf[:read]); err != nil {
		return nil, nil, ifIndex, err
	}
	return &msg, uaddr, ifIndex, nil
}
