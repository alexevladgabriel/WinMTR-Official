package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	dst := "8.8.8.8"
	if len(os.Args) > 1 {
		dst = os.Args[1]
	}

	fmt.Printf("Testing ICMP to %s (pid=%d, id=%d)\n", dst, os.Getpid(), os.Getpid()&0xffff)

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("ListenPacket error: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	pc := c.IPv4PacketConn()
	id := os.Getpid() & 0xffff

	// Test 1: Simple ping (TTL=64, should get Echo Reply)
	fmt.Println("\n--- Test 1: Ping (TTL=64) ---")
	if err := pc.SetTTL(64); err != nil {
		fmt.Printf("SetTTL(64) error: %v\n", err)
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("HELLO")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	dstAddr := &net.IPAddr{IP: net.ParseIP(dst)}
	c.SetDeadline(time.Now().Add(3 * time.Second))

	n, err := c.WriteTo(wb, dstAddr)
	fmt.Printf("WriteTo: n=%d, err=%v\n", n, err)

	buf := make([]byte, 1500)
	for i := 0; i < 5; i++ {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			fmt.Printf("ReadFrom error: %v\n", err)
			break
		}
		fmt.Printf("ReadFrom: n=%d, from=%v, data[0:4]=%x\n", n, from, buf[:min(4, n)])

		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			// Maybe IP header included?
			if len(buf) > 20 && (buf[0]>>4) == 4 {
				ihl := int(buf[0]&0x0f) * 4
				rm, err = icmp.ParseMessage(1, buf[ihl:n])
				if err != nil {
					fmt.Printf("ParseMessage (with IP skip) error: %v\n", err)
					continue
				}
				fmt.Printf("  (had IP header, skipped %d bytes)\n", ihl)
			} else {
				fmt.Printf("ParseMessage error: %v\n", err)
				continue
			}
		}
		fmt.Printf("  Type=%v, Code=%d\n", rm.Type, rm.Code)
		if echo, ok := rm.Body.(*icmp.Echo); ok {
			fmt.Printf("  Echo: ID=%d, Seq=%d\n", echo.ID, echo.Seq)
		}
	}

	// Test 2: TTL=1, should get Time Exceeded
	fmt.Println("\n--- Test 2: TTL=1 (expect Time Exceeded) ---")
	if err := pc.SetTTL(1); err != nil {
		fmt.Printf("SetTTL(1) error: %v\n", err)
	}

	msg2 := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 2, Data: []byte("HELLO")},
	}
	wb2, err := msg2.Marshal(nil)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	c.SetDeadline(time.Now().Add(3 * time.Second))
	n, err = c.WriteTo(wb2, dstAddr)
	fmt.Printf("WriteTo: n=%d, err=%v\n", n, err)

	for i := 0; i < 5; i++ {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			fmt.Printf("ReadFrom error: %v\n", err)
			break
		}
		fmt.Printf("ReadFrom: n=%d, from=%v, data[0:4]=%x\n", n, from, buf[:min(4, n)])

		// Try parsing with and without IP header
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			if len(buf) > 20 && (buf[0]>>4) == 4 {
				ihl := int(buf[0]&0x0f) * 4
				rm, err = icmp.ParseMessage(1, buf[ihl:n])
				if err != nil {
					fmt.Printf("ParseMessage error: %v\n", err)
					continue
				}
				fmt.Printf("  (had IP header, skipped %d bytes)\n", ihl)
			} else {
				fmt.Printf("ParseMessage error: %v\n", err)
				continue
			}
		}
		fmt.Printf("  Type=%v, Code=%d\n", rm.Type, rm.Code)
		if rm.Type == ipv4.ICMPTypeTimeExceeded {
			fmt.Printf("  GOT TIME EXCEEDED from %v\n", from)
			if te, ok := rm.Body.(*icmp.TimeExceeded); ok {
				fmt.Printf("  Data len=%d\n", len(te.Data))
				if len(te.Data) >= 28 {
					origIHL := int(te.Data[0]&0x0f) * 4
					if len(te.Data) >= origIHL+8 {
						origICMP := te.Data[origIHL:]
						origID := int(origICMP[4])<<8 | int(origICMP[5])
						origSeq := int(origICMP[6])<<8 | int(origICMP[7])
						fmt.Printf("  Embedded: origID=%d, origSeq=%d (our id=%d)\n", origID, origSeq, id)
					}
				}
			}
			if raw, ok := rm.Body.(*icmp.RawBody); ok {
				fmt.Printf("  RawBody Data len=%d\n", len(raw.Data))
			}
		}
	}

	fmt.Println("\nDone.")
}
