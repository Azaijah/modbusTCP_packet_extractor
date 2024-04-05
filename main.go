package main

import (
	"encoding/hex"
	"fmt"

	log "github.com/sirupsen/logrus"

	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	capture()

}

type ModbusTCP struct {
	TransactionID uint32
	ProtocolID    uint16
	Length        uint16
	UnitID        uint16
	Modbus        Modbus
	Payload       string
}

type Modbus struct {
	FunctionCode uint8
	Data         string
}

func (mbl *ModbusTCP) DecodeStructFromBytes(data []byte) error {

	hdata := hex.EncodeToString(data)

	log.Info(hdata)

	tid, err := strconv.ParseInt(hdata[0:4], 16, 32)
	if err != nil {
		log.Error(err)
	}
	pid, err := strconv.ParseInt(hdata[4:8], 16, 16)
	if err != nil {
		log.Error(err)
	}
	len, err := strconv.ParseInt(hdata[8:12], 16, 16)
	if err != nil {
		log.Error(err)
	}
	uid, err := strconv.ParseInt(hdata[12:14], 16, 16)
	if err != nil {
		log.Error(err)
	}

	fcode, err := strconv.ParseInt(hdata[14:16], 16, 8)
	if err != nil {
		fcode, err = strconv.ParseInt(hdata[14:15], 16, 8)
		if err != nil {
			log.Fatal(err)
		}
	}

	mbl.TransactionID = uint32(tid)
	mbl.ProtocolID = uint16(pid)
	mbl.Length = uint16(len)
	mbl.UnitID = uint16(uid)
	mbl.Modbus.FunctionCode = uint8(fcode)
	mbl.Modbus.Data = hdata[16:]
	mbl.Payload = hdata[14:]

	return nil
}

func capture() {

	handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("src port 502")
	if err != nil {
		log.Fatal(err)
	}

	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packets.Packets() {

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.Payload != nil && len(tcp.Payload) > 0 {
				mbus := ModbusTCP{}
				mbus.DecodeStructFromBytes(tcp.BaseLayer.Payload)

				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				ip, _ := ipLayer.(*layers.IPv4)

				log.Infof("Modbus packet extracted: IP: %s -> %s", ip.SrcIP.String(), ip.DstIP.String())

				fmt.Printf("Transaction Identifier: %d \n", mbus.TransactionID)
				fmt.Printf("Protocol Identifier: %d \n", mbus.ProtocolID)
				fmt.Printf("Length: %d \n", mbus.Length)
				fmt.Printf("Unit Identifier: %d \n", mbus.UnitID)
				fmt.Printf("Function code: %d \n", mbus.Modbus.FunctionCode)
				fmt.Printf("Data: %s \n", mbus.Modbus.Data)

				fmt.Printf("************************ \n")
			}
		} else {
			log.Error(packet.ErrorLayer())
		}

	}

}
