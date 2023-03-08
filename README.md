# tfrk-assessment

package main

import (
    "fmt"
    "net"
    "net/http"
    "bytes"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

func main() {
    listenAddr := ":6000" // listening address and port
    conn, err := net.ListenPacket("udp", listenAddr)
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    fmt.Println("Listening on", listenAddr)

    buffer := make([]byte, 1500) // maximum size of Ethernet frame

    for {
        n, addr, err := conn.ReadFrom(buffer)
        if err != nil {
            fmt.Println("Error reading packet:", err)
            continue
        }

        fmt.Printf("Received %d bytes from %s\n", n, addr.String())

        // decode packet using gopacket
        packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeEthernet, gopacket.Default)
        ethLayer := packet.Layer(layers.LayerTypeEthernet)
        if ethLayer == nil {
            fmt.Println("Error decoding Ethernet layer")
            continue
        }
        eth := ethLayer.(*layers.Ethernet)

        // check for Geneve protocol (EtherType 0x6558)
        if eth.EthernetType == layers.EthernetType(0x6558) {
            var geneve layers.GENEVE
            err := geneve.DecodeFromBytes(buffer[14:], gopacket.NilDecodeFeedback)
            if err != nil {
                fmt.Println("Error decoding Geneve layer:", err)
                continue
            }

            // check for VXLAN protocol (EtherType 0x0800)
            if geneve.NextProtID == layers.IPProtocolUDP && geneve.VNI != 0 {
                var vxlan layers.VXLAN
                err := vxlan.DecodeFromBytes(geneve.Payload, gopacket.NilDecodeFeedback)
                if err != nil {
                    fmt.Println("Error decoding VXLAN layer:", err)
                    continue
                }

                // decapsulate VXLAN packet
                payload := vxlan.Payload

                // forward payload to HTTP server
                httpClient := http.Client{}
                httpReq, err := http.NewRequest(http.MethodPost, "http://localhost:8080", bytes.NewReader(payload))
                if err != nil {
                    fmt.Println("Error creating HTTP request:", err)
                    continue
                }
                _, err = httpClient.Do(httpReq)
                if err != nil {
                    fmt.Println("Error sending HTTP request:", err)
                    continue
                }

                fmt.Printf("Forwarded %d bytes to HTTP server\n", len(payload))
            } else {
                fmt.Println("Not a VXLAN packet")
                continue
            }
        } else {
            fmt.Println("Not a Geneve packet")
            continue
        }
    }
}
