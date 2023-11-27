package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"strconv"
	"strings"
)

func main() {
	// Load the IP ranges
	loadIPRanges()

	// Listen for incoming UDP packets on port 53 (DNS) on all interfaces
	pc, err := net.ListenPacket("udp", ":53")
    	if err != nil {
    		fmt.Println("error listening:", err)
    		os.Exit(1)
    	}
    	defer func(pc net.PacketConn) {
    		err := pc.Close()
    		if err != nil {
    			fmt.Println("error closing:", err)
    		}
    }(pc)

    for {
       	buf := make([]byte, 4096)
       	n, addr, err := pc.ReadFrom(buf)
       	if err != nil {
       		fmt.Println("error reading:", err)
       		continue
       	}
        go handleRequest(pc, addr, buf[:n])
    }

		// Handle the packet in a separate goroutine
		go func() {
			var modified = false

			// Forward the packet to the upstream DNS server
			c, err := net.Dial("udp", "8.8.8.8:53")
			if err != nil {
				return
			}
			defer func(c net.Conn) {
				err := c.Close()
				if err != nil {
					//fmt.Println("Error closing connection: ", err)
				}
			}(c)

			// Send the request to the upstream DNS server
			_, err2 := c.Write(buf[:n])
			if err2 != nil {
				return
			}

			// Read the response from the upstream DNS server
			buf2 := make([]byte, 1024)
			_, err = c.Read(buf2)
			if err != nil {
				return
			}

			// Parse the response
			packet := gopacket.NewPacket(buf2, layers.LayerTypeDNS, gopacket.Default)
			dnsPacket := packet.Layer(layers.LayerTypeDNS)


			if !modified {
				// Send the response back to the client
				_, err3 := pc.WriteTo(packet.Data(), addr)
				if err3 != nil {
					return
				}
			} else {
				// Send the response back to the client
				// create new packet to send back to client
				buf3 := gopacket.NewSerializeBuffer()

				//fmt.Println("Sending modified response to client")

				err4 := packet.Layer(layers.LayerTypeDNS).(*layers.DNS).SerializeTo(buf3, gopacket.SerializeOptions{})
				if err4 != nil {
					return
				}

				// Send the response back to the client
				_, err3 := pc.WriteTo(buf3.Bytes(), addr)
				if err3 != nil {
					return
				}

			}
		}()

	}
}


func handleRequest(pc net.PacketConn, addr net.Addr, buf []byte) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println("error dialing:", err)
		return
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("error closing:", err)
		}
	}(conn)

	if _, err := conn.Write(buf); err != nil {
		fmt.Println("error writing:", err)
		return
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Println("error reading:", err)
		return
	}

	packet := gopacket.NewPacket(resp[:n], layers.LayerTypeDNS, gopacket.Default)
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		fmt.Println(string(dns.Questions[0].Name))
		tcp, err1 := dnsPacket.(*layers.DNS)
        			if !err1 {
        				fmt.Println("No DNS packet found")
        				panic(err1)
        			}

        			var domain = "No Record Found"
        			if len(tcp.Answers) > 0 {
        				domain = tcp.Answers[len(tcp.Answers)-1].IP.String()
        			}

        			var record = "No Domain Found"
        			if len(tcp.Questions) > 0 {
        				record = tcp.Questions[0].Type.String() + " : " + string(tcp.Questions[0].Name)
        			}

        			var ARecord []net.IP
        			var AAAARecord []net.IP
        			var CNAMERecord [][]byte

        			for _, answer := range tcp.Answers {
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

        			var cdn = ""
        			// check for CDN
        			if len(tcp.Answers) > 0 {
        				cdn = checkForCANEfficient(ARecord, AAAARecord, CNAMERecord)
        				// Print the request and response
        				fmt.Println("Received request from ", addr, ": ", domain, " -> ", record, " : ", cdn)
        			}

        			if cdn != "" || cdn != "ipv6" {
        				//fmt.Println("CDN: ", cdn)
        				var ipv6Present = false
        				for _, answer := range tcp.Answers {
        					if answer.Type == layers.DNSTypeAAAA {
        						ipv6Present = true
        						break
        					}
        				}

        				if !ipv6Present {
        					switch cdn {
        					case "fastly":
        						// Fastly
        						fmt.Println("Modifying response for Fastly")
        						var ip = "2a04:4e42::"
        						var stripling []string
        						var ipAddressInt []int

        						modified = true

        						name := tcp.Questions[0].Name
        						if len(tcp.Answers) > 0 {
        							name = tcp.Answers[len(tcp.Answers)-1].Name
        							stripling = strings.Split(tcp.Answers[len(tcp.Answers)-1].IP.String(), ".")
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

        						// Add the IPv6 address to the response
        						packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers = append(packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers, layers.DNSResourceRecord{
        							Name:  name,
        							Type:  layers.DNSTypeAAAA,
        							Class: layers.DNSClassIN,
        							IP:    net.ParseIP(ip),
        							TTL:   60,
        						})
        						packet.Layer(layers.LayerTypeDNS).(*layers.DNS).ANCount++

        					case "cloudflare":
        						// Cloudflare
        						fmt.Println("Modifying response for Cloudflare")
        						modified = true

        						name := tcp.Questions[0].Name
        						if len(tcp.Answers) > 0 {
        							name = tcp.Answers[len(tcp.Answers)-1].Name
        						}

        						// Add the IPv6 address to the response
        						packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers = append(packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers, layers.DNSResourceRecord{
        							Name:  name,
        							Type:  layers.DNSTypeAAAA,
        							Class: layers.DNSClassIN,
        							IP:    net.ParseIP("2606:4700:7::a29f:9804"),
        							TTL:   60,
        						})
        						packet.Layer(layers.LayerTypeDNS).(*layers.DNS).ANCount++

        					}
        				}
        			}
	}

	if _, err := pc.WriteTo(packet.Data()[:n], addr); err != nil {
		fmt.Println("error writing:", err)
		return
	}
}

func checkForCANEfficient(ARecords []net.IP, AAAARecords []net.IP, CNAMERecords [][]byte) string {
	if len(AAAARecords) < 1 {
		if len(ARecords) > 0 {
			if len(CNAMERecords) > 0 {
				var firstRecord = CNAMERecords[0]
				var lastRecord = CNAMERecords[len(CNAMERecords)-1]

				if checkForAkamai(firstRecord) {
					return "akamai"
				}
				if checkForS3(firstRecord) {
					return "s3"
				}
				if checkForMsEdge(firstRecord) {
					return "msedge"
				}
				if checkForAzureEdge(firstRecord) {
					return "azureedge"
				}

				if checkForAkamai(lastRecord) {
					return "akamai"
				}
				if checkForS3(lastRecord) {
					return "s3"
				}
				if checkForMsEdge(lastRecord) {
					return "msedge"
				}
				if checkForAzureEdge(lastRecord) {
					return "azureedge"
				}
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
			}
		} else {
			return ""
		}
	} else {
		return "ipv6"
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
	} else if strings.Contains(string(cname), "live.com") {
		return true
	} else if strings.Contains(string(cname), "trafficmanager.net") {
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
		} else {
			return false
		}
	}
	return false
}

func checkForBunnyCDN(ip net.IP) bool {
	// BunnyCDN IP ranges
	for _, bunnyCDNIP := range bunnyCDN {
		if bunnyCDNIP.Equal(ip) {
			return true
		} else {
			return false
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
			return true
		} else {
			return false
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
	if fastly[0].Contains(ip) || fastly[1].Contains(ip) || fastly[2].Contains(ip) || fastly[3].Contains(ip) || fastly[4].Contains(ip) || fastly[5].Contains(ip) || fastly[6].Contains(ip) || fastly[7].Contains(ip) || fastly[8].Contains(ip) || fastly[9].Contains(ip) || fastly[10].Contains(ip) || fastly[11].Contains(ip) {
		return true
	} else {
		return false
	}
}

func checkForCloudFlare(ip net.IP) bool {
	// CloudFlare IP ranges
	if cloudflare[0].Contains(ip) || cloudflare[1].Contains(ip) || cloudflare[2].Contains(ip) || cloudflare[3].Contains(ip) || cloudflare[4].Contains(ip) || cloudflare[5].Contains(ip) || cloudflare[6].Contains(ip) || cloudflare[7].Contains(ip) || cloudflare[8].Contains(ip) || cloudflare[9].Contains(ip) || cloudflare[10].Contains(ip) || cloudflare[11].Contains(ip) || cloudflare[12].Contains(ip) || cloudflare[13].Contains(ip) || cloudflare[14].Contains(ip) {
		return true
	} else {
		return false
	}
}
