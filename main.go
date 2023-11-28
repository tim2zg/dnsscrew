package main

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"os"
	"strconv"
	"strings"
)

var upstreamDnsServer string

func main() {
	// Load the IP ranges
	loadIPRanges()
	fmt.Println("Starting DNS server on port 53")
	upstreamDnsServer = "10.0.1.1"
	if os.Getenv("UPSTREAM_DNS_SERVER") != "" {
		upstreamDnsServer = os.Getenv("UPSTREAM_DNS_SERVER")
	}
	fmt.Println("Using upstream DNS server: " + upstreamDnsServer)
	serveUDPDNSServer()
}

func serveUDPDNSServer() {
	// Listen for incoming UDP packets on port 53 (DNS) on all interfaces
	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		fmt.Println("error listening:", err)
		os.Exit(1)
	}

	// Keep connection open
	defer func(pc net.PacketConn) {
		err := pc.Close()
		if err != nil {
			fmt.Println("error closing:", err)
		}
	}(pc)

	// Main receiving loop
	for {
		// Read request
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Println("error reading:", err)
			continue
		}

		go handleRequest(pc, addr, buf[:n])
	}
}

func handleRequest(pc net.PacketConn, addr net.Addr, buf []byte) {
	fmt.Println("------------------")
	fmt.Println("Received request from ", addr)

	// Parse the request
	clientPacket := gopacket.NewPacket(buf, layers.LayerTypeDNS, gopacket.Default)

	// Check for DNS layer
	if dnsLayer := clientPacket.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		// Check if ipv4 or ipv6 is requested
		if dns.Questions[0].Type == layers.DNSTypeA {
			fmt.Println("Making upstream request for A record")
			fmt.Println("Domain: " + string(dns.Questions[0].Name))
			// make upstream request for A record
			askUpstreamProxy(buf, addr, pc)
		} else if dns.Questions[0].Type == layers.DNSTypeAAAA {
			fmt.Println("Making upstream request for AAAA record")
			fmt.Println("Domain: " + string(dns.Questions[0].Name))
			// make an upstream request for AAAA record
			_, ARecord, AAAARecord, _, upStreamPacket, n, err := makeProxyDownstream(buf, addr)
			if err != nil {
				fmt.Println("error making proxy downstream:", err)
				return
			}

			if len(AAAARecord) == 0 {
				if ARecord != nil {
					if ARecord[0].Equal(net.ParseIP("10.10.10.1")) {
						fmt.Println("IPv4 address is Blackholed")
					} else {
						beFunnyWithIPv6(clientPacket, upStreamPacket, pc, n, addr)
					}
				}
			} else {
				// Pass down from proxy
				if _, err := pc.WriteTo(upStreamPacket.Data()[:n], addr); err != nil {
					fmt.Println("error writing:", err)
					return
				}
			}
		} else {
			// Make proxy request upstream for other record
			askUpstreamProxy(buf, addr, pc)
		}
	} else {
		fmt.Println("Error parsing DNS packet")
	}
	return
}

func askUpstreamProxy(buf []byte, addr net.Addr, pc net.PacketConn) {
	// Make proxy request downstream
	_, _, _, _, upStreamPacket, n, err := makeProxyDownstream(buf, addr)
	if err != nil {
		fmt.Println("error making proxy downstream:", err)
		return
	}

	// Pass down from proxy
	if _, err := pc.WriteTo(upStreamPacket.Data()[:n], addr); err != nil {
		fmt.Println("error writing:", err)
		return
	}
}

func beFunnyWithIPv6(questionPacket gopacket.Packet, emptyIPv6response gopacket.Packet, pc net.PacketConn, n int, addr net.Addr) {
	// make a ipv4 request
	upstreamPackage := queryDNS(questionPacket)
	if upstreamPackage == nil {
		fmt.Println("Error getting A response to modify")
	}

	// Get the A, AAAA and CNAME records
	var ARecord []net.IP
	var CNAMERecord [][]byte
	for _, answer := range upstreamPackage.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers {
		if answer.Type == layers.DNSTypeA {
			ARecord = append(ARecord, answer.IP)
		}
		if answer.Type == layers.DNSTypeCNAME {
			CNAMERecord = append(CNAMERecord, answer.CNAME)
		}
	}

	CNAMERecord = append(CNAMERecord, questionPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions[0].Name)
	if len(upstreamPackage.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers) > 0 {
		CNAMERecord = append(CNAMERecord, upstreamPackage.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers[len(upstreamPackage.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers)-1].Name)
	}

	fmt.Println("A record: " + ARecord[0].String())

	// detect CDN
	cdn := checkForCANEfficient(ARecord, CNAMERecord)
	fmt.Println("Detected: " + cdn)

	if cdn != "" {
		// get the ip address
		ip := modifyResponse(upstreamPackage, cdn, ARecord, CNAMERecord)

		// Modify the response
		returnPacket := questionPacket
		var dnsAnswer layers.DNSResourceRecord
		dnsAnswer.Type = layers.DNSTypeAAAA
		dnsAnswer.IP = ip
		dnsAnswer.Name = questionPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions[0].Name
		dnsAnswer.Class = layers.DNSClassIN
		dnsAnswer.TTL = 300
		returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).QR = true
		returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).ANCount = 1
		returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).OpCode = layers.DNSOpCodeQuery
		returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).AA = true
		returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers = append(returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers, dnsAnswer)
		returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).ResponseCode = layers.DNSResponseCodeNoErr

		// Send the response back to the client
		// create new packet to send back to client
		moddedPacketData := gopacket.NewSerializeBuffer()

		err4 := returnPacket.Layer(layers.LayerTypeDNS).(*layers.DNS).SerializeTo(moddedPacketData, gopacket.SerializeOptions{})
		if err4 != nil {
			return
		}

		// Send the response back to the client
		_, err3 := pc.WriteTo(moddedPacketData.Bytes(), addr)
		if err3 != nil {
			return
		}
	} else {
		// Pass empty response
		if _, err := pc.WriteTo(emptyIPv6response.Data()[:n], addr); err != nil {
			fmt.Println("error writing:", err)
			return
		}
	}
}

func queryDNS(original gopacket.Packet) gopacket.Packet {
	// change request from ipv6 to ipv4

	original.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions[0].Type = layers.DNSTypeA

	// making new connection to the upstream dns
	address := upstreamDnsServer + ":53"
	conn, err := net.Dial("udp", address)
	if err != nil {
		fmt.Println("error dialing:", err)
		return nil
	}

	// keep connection open
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("error closing:", err)
		}
	}(conn)

	// creating new package buffer
	moddedPacketData := gopacket.NewSerializeBuffer()

	// serializing new package to buffer
	err4 := original.Layer(layers.LayerTypeDNS).(*layers.DNS).SerializeTo(moddedPacketData, gopacket.SerializeOptions{})
	if err4 != nil {
		return nil
	}

	// sending new buffer to upstream dns
	_, err3 := conn.Write(moddedPacketData.Bytes())
	if err3 != nil {
		return nil
	}

	// Read the response from upstream dns
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Println("error reading:", err)
		return nil
	}

	// parsing response into upstream package
	upstreamPackage := gopacket.NewPacket(resp[:n], layers.LayerTypeDNS, gopacket.Default)

	original.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions[0].Type = layers.DNSTypeAAAA

	return upstreamPackage
}

func makeProxyDownstream(buf []byte, addr net.Addr) (string, []net.IP, []net.IP, [][]byte, gopacket.Packet, int, error) {
	// Create a connection a DNS Server
	address := upstreamDnsServer + ":53"
	conn, err := net.Dial("udp", address)
	if err != nil {
		fmt.Println("error dialing:", err)
		return "", nil, nil, nil, nil, 0, err
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("error closing:", err)
		}
	}(conn)

	// Send the request to a DNS server
	if _, err := conn.Write(buf); err != nil {
		fmt.Println("error writing:", err)
		return "", nil, nil, nil, nil, 0, err
	}

	// Read the response from DNS server
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Println("error reading:", err)
		return "", nil, nil, nil, nil, 0, err
	}

	// Check the response for the domain and record
	domain, ARecord, AAAARecord, CNAMERecord, packet, err := checkDNSPacket(resp, n, addr)
	if err != nil {
		fmt.Println("error checking DNS packet:", err)
		return "", nil, nil, nil, nil, 0, err
	}
	return domain, ARecord, AAAARecord, CNAMERecord, packet, n, nil
}

func checkDNSPacket(resp []byte, n int, addr net.Addr) (string, []net.IP, []net.IP, [][]byte, gopacket.Packet, error) {
	// Parse the response
	packet := gopacket.NewPacket(resp[:n], layers.LayerTypeDNS, gopacket.Default)
	// Check for DNS layer
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		// Get the record
		var domain = "No Domain Found"
		if len(dns.Questions) > 0 {
			domain = dns.Questions[0].Type.String() + " : " + string(dns.Questions[0].Name)
		}

		// Get the A, AAAA and CNAME records
		var ARecord []net.IP
		var AAAARecord []net.IP
		var CNAMERecord [][]byte
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA {
				ARecord = append(ARecord, answer.IP)
			}
			if answer.Type == layers.DNSTypeAAAA {
				AAAARecord = append(AAAARecord, answer.IP)
			}
			if answer.Type == layers.DNSTypeCNAME {
				CNAMERecord = append(CNAMERecord, answer.CNAME)
			}
		}
		domain = string(dns.Questions[0].Name)
		return domain, ARecord, AAAARecord, CNAMERecord, packet, nil
	}
	return "", nil, nil, nil, nil, nil
}

func modifyResponse(serverPackage gopacket.Packet, cdn string, ARecord []net.IP, CNAMERecord [][]byte) net.IP {
	dns := serverPackage.Layer(layers.LayerTypeDNS).(*layers.DNS)

	switch cdn {
	case "fastly":
		// Fastly
		fmt.Println("Modifying response for Fastly")
		var ip = "2a04:4e42:600::"
		var stripling []string
		var ipAddressInt []int

		if len(dns.Answers) > 0 {
			stripling = strings.Split(dns.Answers[len(dns.Answers)-1].IP.String(), ".")
		}

		for _, ipAddress := range stripling {
			i, err := strconv.Atoi(ipAddress)
			if err != nil {
				panic(err)
			}
			ipAddressInt = append(ipAddressInt, i)
		}

		if len(ARecord) == 1 {
			ip = ip + strconv.Itoa((ipAddressInt[2]%4)*256+(ipAddressInt[3]*1))
		} else {
			ip = ip + strconv.Itoa((ipAddressInt[2]%64)*256+(ipAddressInt[3]*1))
		}

		return net.ParseIP(ip)

	case "cloudflare":
		// Cloudflare
		fmt.Println("Modifying response for Cloudflare")
		return net.ParseIP("2606:4700:7::a29f:9804")

	case "akamai":
		fmt.Println("Modifying for Akamai")
		lastCNAME := CNAMERecord[len(CNAMERecord)-1]
		split := strings.Split(string(lastCNAME), ".")
		ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip6", split[0]+".dsc"+split[1]+"."+split[2]+"."+split[3])
		if err != nil {
			fmt.Println("could not look up ip")
			return net.ParseIP("")
		}
		return net.ParseIP(ips[0].String())

	case "cloudfront":
		// Cloudflare
		fmt.Println("Modifying response for CloudFront")
		return net.ParseIP("2600:9000:25a2:1600:c:132:48e:f021")

	case "bunnycdn":
		//2400:52e0:1e00::722:1
		fmt.Println("Modifying response for Bunny")
		return net.ParseIP("2400:52e0:1e00::722:1")

	case "highwinds":
		fmt.Println("Modifying response for Stackpath")
		return net.ParseIP("2001:4de0:ac18::1:a:1a")

	case "msedge":
		fmt.Println("Modifying for MS edge")
		lastCNAME := CNAMERecord[len(CNAMERecord)-1]
		split := strings.Split(string(lastCNAME), "-")

		var stripling []string
		var ipAddressInt []int

		if len(dns.Answers) > 0 {
			stripling = strings.Split(dns.Answers[len(dns.Answers)-1].IP.String(), ".")
		}

		for _, ipAddress := range stripling {
			i, err := strconv.Atoi(ipAddress)
			if err != nil {
				panic(err)
			}
			ipAddressInt = append(ipAddressInt, i)
		}

		IPRange := ""
		switch split[0] {
		case "a":
			IPRange = "2620:1ec:c11::"
		case "b":
			IPRange = "2620:1ec:a92::"
		case "c":
			IPRange = "2a01:111:2003::"
		case "l":
			IPRange = "2620:1ec:21::"
		case "s":
			IPRange = "2620:1ec:6::"
		case "k":
			IPRange = "2620:1ec:c::"
		case "t":
			IPRange = "2620:1ec:bdf::"
		case "spo":
			IPRange = "2620:1ec:8f8::"
			if ipAddressInt[3] == 9 {
				ipAddressInt[3] = 8
			}
		default:
			IPRange = "2620:1ec:21::"
		}

		if len(ARecord) == 1 {
			IPRange = IPRange + strconv.Itoa(ipAddressInt[3])
		}

		return net.ParseIP(IPRange)

	case "azureedge":
		fmt.Println("Modifying for Azure edge")
		lastCNAME := CNAMERecord[len(CNAMERecord)-1]
		split := strings.Split(string(lastCNAME), ".")
		split[0] = "cs21"

		if len(split) >= 4 {
			var validAAAA net.IP
			ips, err := net.LookupIP(split[0] + "." + split[1] + "." + split[2] + "." + split[3])
			if err != nil {
				fmt.Println("could not look up ip")
			}
			for _, ip := range ips {
				if strings.Contains(ip.String(), ":") {
					validAAAA = ip
				}
			}

			return validAAAA
		}

	case "sucuri":
		//2a02:fe80:1010::21
		// Sucuri
		fmt.Println("Modifying response for Sucuri")
		return net.ParseIP("2a02:fe80:1010::21")

	case "github":
		// Fastly GH
		fmt.Println("Modifying response for GitHub")
		var ip = "2606:50c0:8000::"
		var stripling []string
		var ipAddressInt []int

		if len(dns.Answers) > 0 {
			stripling = strings.Split(dns.Answers[len(dns.Answers)-1].IP.String(), ".")
		}

		for _, ipAddress := range stripling {
			i, err := strconv.Atoi(ipAddress)
			if err != nil {
				panic(err)
			}
			ipAddressInt = append(ipAddressInt, i)
		}

		ip = ip + strconv.Itoa(ipAddressInt[3])

		return net.ParseIP(ip)

	case "edge":
		//edge
		fmt.Println("Modifying response for Edge")
		return net.ParseIP("2606:2800:133:672:1e5f:2264:1854:1189")

	case "s3":
		lastCNAME := CNAMERecord[1]
		fmt.Println(string(lastCNAME))

		domain := fixHostname(string(lastCNAME))
		var validAAAA net.IP
		ips, err := net.LookupIP(domain)
		if err != nil {
			fmt.Println("could not look up ip")
		}
		for _, ip := range ips {
			if strings.Contains(ip.String(), ":") {
				validAAAA = ip
			}
		}

		return validAAAA

	}
	return nil
}

func checkForCANEfficient(ARecords []net.IP, CNAMERecords [][]byte) string {
	if len(ARecords) > 0 {
		// get the last cname
		lastcname := CNAMERecords[len(CNAMERecords)-1]
		if checkForAzureEdge(lastcname) {
			return "azureedge"
		}
		if checkForAkamai(lastcname) {
			return "akamai"
		}
		if checkForS3(lastcname) {
			return "s3"
		}
		if checkForMsEdge(lastcname) {
			return "msedge"
		}

		for _, ip := range ARecords {
			if checkForFastly(ip) {
				return "fastly"
			}
			if checkForCloudFlare(ip) {
				return "cloudflare"
			}
			if checkForCloudFront(ip) {
				return "cloudfront"
			}
			if checkForBunnyCDN(ip) {
				return "bunnycdn"
			}
			if checkForHighwinds(ip) {
				return "highwinds"
			}
			if checkSucuri(ip) {
				return "sucuri"
			}
			if checkForGithub(ip) {
				return "github"
			}
			if checkForEdge(ip) {
				return "edge"
			}
			if checkForMsEdgeIP(ip) {
				return "msedge"
			}
		}
		for _, cname := range CNAMERecords {
			if checkForAzureEdge(cname) {
				return "azureedge"
			}
			if checkForAkamai(cname) {
				return "akamai"
			}
			if checkForS3(cname) {
				return "s3"
			}
			if checkForMsEdge(cname) {
				return "msedge"
			}
		}
	} else {
		return ""
	}
	return ""
}

func checkForGithub(ip net.IP) bool {
	if gitHubIPS.Contains(ip) {
		return true
	} else {
		return false
	}
}

func checkSucuri(ip net.IP) bool {
	if sucuri[0].Contains(ip) || sucuri[1].Contains(ip) || sucuri[2].Contains(ip) || sucuri[3].Contains(ip) || sucuri[4].Contains(ip) || sucuri[5].Contains(ip) || sucuri[6].Contains(ip) || sucuri[7].Contains(ip) || sucuri[8].Contains(ip) || sucuri[9].Contains(ip) || sucuri[10].Contains(ip) || sucuri[11].Contains(ip) || sucuri[12].Contains(ip) || sucuri[13].Contains(ip) || sucuri[14].Contains(ip) {
		return true
	} else {
		return false
	}
}

func checkForAzureEdge(cname []byte) bool {
	if strings.Contains(string(cname), "v0cdn.net") {
		return true
	} else if strings.Contains(string(cname), "trafficmanager.net") {
		return true
	} else {
		return false
	}
}

func checkForMsEdge(cname []byte) bool {
	if strings.Contains(string(cname), "msedge.net") {
		return true
	} else {
		return false
	}
}

func checkForMsEdgeIP(ip net.IP) bool {
	if msedge[0].Contains(ip) {
		return true
	} else {
		return false
	}
}

func checkForHighwinds(ip net.IP) bool {
	// StackPath IP ranges
	for _, stackPathIp := range stackPath {
		if stackPathIp.Contains(ip) {
			return true
		}
	}
	return false
}

func checkForEdge(ip net.IP) bool {
	// Edge IP ranges
	for _, edge := range edgeIo {
		if edge.Contains(ip) {
			return true
		}
	}
	return false
}

func checkForBunnyCDN(ip net.IP) bool {
	// BunnyCDN IP ranges
	for _, bunnyCDNIP := range bunnyCDN {
		if bunnyCDNIP.Equal(ip) {
			return true
		}
	}
	return false
}

func checkForS3(cname []byte) bool {
	if strings.Contains(string(cname), ".amazonaws.com") {
		return true
	} else {
		return false
	}
}

func checkForCloudFront(ip net.IP) bool {
	// CloudFront IP ranges
	for _, cloudFrontIp := range cloudFront {
		if cloudFrontIp.Contains(ip) {
			fmt.Println()
			return true
		}
	}
	return false
}

func checkForAkamai(cname []byte) bool {
	if strings.Contains(string(cname), "akadns.net") || strings.Contains(string(cname), "akamaiedge.net") {
		return true
	} else {
		return false
	}
}

func checkForFastly(ip net.IP) bool {
	// Fastly IP ranges
	if fastly[0].Contains(ip) || fastly[1].Contains(ip) || fastly[2].Contains(ip) || fastly[3].Contains(ip) || fastly[4].Contains(ip) || fastly[5].Contains(ip) || fastly[6].Contains(ip) || fastly[7].Contains(ip) || fastly[8].Contains(ip) || fastly[9].Contains(ip) || fastly[10].Contains(ip) || fastly[11].Contains(ip) || fastly[12].Contains(ip) {
		return true
	} else {
		return false
	}
}

func checkForCloudFlare(ip net.IP) bool {
	// CloudFlare IP ranges
	if cloudflare[0].Contains(ip) || cloudflare[1].Contains(ip) || cloudflare[2].Contains(ip) || cloudflare[3].Contains(ip) || cloudflare[4].Contains(ip) || cloudflare[5].Contains(ip) || cloudflare[6].Contains(ip) || cloudflare[7].Contains(ip) || cloudflare[8].Contains(ip) || cloudflare[9].Contains(ip) || cloudflare[10].Contains(ip) || cloudflare[11].Contains(ip) || cloudflare[12].Contains(ip) || cloudflare[13].Contains(ip) || cloudflare[14].Contains(ip) || cloudflare[15].Contains(ip) {
		return true
	} else {
		return false
	}
}
