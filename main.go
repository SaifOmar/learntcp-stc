package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

type ARPCache map[string]string

func (c ARPCache) Query(ip string) string {
	if mac, ok := c[ip]; ok {
		return mac
	}
	return "ARP_REQUEST " + ip
}
func (c ARPCache) Entry(ip string, mac string) {
	c[ip] = mac
}

func (c ARPCache) Reply(ip string, mac string) {
	c[ip] = mac
	fmt.Println("cached " + ip + " " + mac)
}

func parseHeader(line string) []byte {
	header, err := hex.DecodeString(line)
	if err != nil {
		panic(err)
	}
	return header

}

func scan() ([]string, error) {
	var lines []string
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func identifyProtocol(line string) {
	buff := parseHeader(line)
	protocol := buff[9]
	switch protocol {
	case TCP:
		fmt.Println("TCP")
	case UDP:
		fmt.Println("UDP")
	case ICMP:
		fmt.Println("ICMP")
	default:
		fmt.Println("OTHER")
	}
	// decimalValue, _ := strconv.ParseUint(string(protocol), 0, 64)
	// fmt.Printf("%d\n", decimalValue)
}
func ipv4Checksum() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		frame := parseHeader(line)
		count := 0
		indx := 0
		var words []uint16
		for {
			if count >= len(frame) {
				break
			}
			d := frame[indx : count+2]
			word := binary.BigEndian.Uint16(d)
			words = append(words, word)
			count += 2
			indx = count
		}
		var sum uint32
		for i, word := range words {
			if i == 5 {
				word = 0
			}
			sum += uint32(word)
		}
		for {
			if sum>>16 != 0 {
				sum = (sum & 0xFFFF) + (sum >> 16)
			} else {
				break
			}

		}
		checksum := ^sum & 0xFFFF
		fmt.Printf("%x\n", checksum)
	}
}

func simulteARP() {
	cache := make(ARPCache)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "ENTRY":
			ip := parts[1]
			mac := parts[2]
			cache.Entry(ip, mac)
		case "REPLY":
			ip := parts[1]
			mac := parts[2]
			cache.Reply(ip, mac)
		case "QUERY":
			ip := parts[1]
			mac := cache.Query(ip)
			fmt.Println(mac)
		default:
			fmt.Println("Unknown command")
		}
	}
}

// Step 2 of 5 · Exercise, graded on the executor
//
// Build an ICMP Echo Reply
// Build an ICMP Echo Reply from an Echo Request.
//
// Input: one hex-encoded ICMP echo request (RFC 792, type 8 code 0) per line.
//
// For each request, emit the corresponding Echo Reply as hex (lowercase, no spaces):
//
// Same id, sequence number, and decoded.
// Type = 0 (Echo Reply), Code = 0.
// Recompute the 16-bit one's complement checksum over the entire ICMP message with the checksum field zeroed.
// If the input does not start with type=8 (i.e. it isn't an echo request), produce no output line for it.
//
// Example:
//
// INPUT:  0800f7ff0001000168656c6c6f          (type=8, csum=f7ff, id=1, seq=1, "hello")
// OUTPUT: 0000bc2b0001000168656c6c6f          (type=0, recomputed csum=bc2b)
func icmp() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		decoded := parseHeader(line)
		cpDecoded := make([]byte, len(decoded))
		copy(cpDecoded, decoded)
		if decoded[0] == 8 {
			// zero
			cpDecoded[0] = 0 // Type -> Echo Reply
			cpDecoded[2] = 0 // checksum byte 1
			cpDecoded[3] = 0 // checksum byte 2
			// pad
			if len(cpDecoded)%2 != 0 {
				cpDecoded = append(cpDecoded, 0)
			}
			var words []uint16
			count := 0
			indx := 0
			for {
				if count >= len(cpDecoded) {
					break
				}
				// if count == len(cpDecoded)-1 {
				// 	break
				// }
				d := cpDecoded[indx : count+2]
				word := binary.BigEndian.Uint16(d)
				words = append(words, word)
				count += 2
				indx = count
			}
			var sum uint32
			for _, word := range words {
				sum += uint32(word)
			}
			for {
				if sum>>16 != 0 {
					sum = (sum & 0xFFFF) + (sum >> 16)
				} else {
					break
				}

			}
			checksum := ^sum & 0xFFFF
			cpDecoded[2] = byte(checksum >> 8)
			cpDecoded[3] = byte(checksum)
			if len(cpDecoded) > len(decoded) {
				cpDecoded = cpDecoded[:len(decoded)]
			}
			fmt.Printf("%x\n", cpDecoded)
		}
	}
}

// Step 2 of 5 · Exercise, graded on the executor
//
// Parse UDP Header
// Parse a UDP header.
//
// Input: 8 hex bytes (UDP header, RFC 768): 2B src port | 2B dst port | 2B length | 2B checksum, all big-endian.
//
// Output: <src_port> <dst_port> <length> <checksum_hex> (ports and length in decimal; checksum as 4 lowercase hex chars).
//
// Example:
//
// INPUT:  04d2162e000c1bc4
// OUTPUT: 1234 5678 12 1bc4

func UPDheaders() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var decoded []byte
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}

		decoded = parseHeader(line)
		if decoded == nil {
			continue
		} else {
			break
		}
	}

	sourcePort := binary.BigEndian.Uint16(decoded[0:2])
	destinationPort := binary.BigEndian.Uint16(decoded[2:4])
	length := binary.BigEndian.Uint16(decoded[4:6])
	checksum := binary.BigEndian.Uint16(decoded[6:])
	fmt.Printf("%d %d %d %04x\n",
		sourcePort,
		destinationPort,
		length,
		checksum,
	)
}

// Step 2 of 5 · Exercise, graded on the executor
//
// TCP Flags
// Decode the 8 TCP flag bits at offset 13 of a TCP header.
//
// Input: one hex byte per line.
//
// Bit layout (RFC 793 + RFC 3168 ECN), from least-significant to most-significant:
//
// bit	name
// 0	FIN
// 1	SYN
// 2	RST
// 3	PSH
// 4	ACK
// 5	URG
// 6	ECE
// 7	CWR
// Output a comma-separated list of set flag names in ascending bit order, or NONE if no flags are set.
//
// Example:
//
// INPUT:  12          (= 0b00010010 = SYN bit + ACK bit)
// OUTPUT: SYN,ACK
func TCPflags() {
	const (
		FIN = 1 << iota
		SYN
		RST
		PSH
		ACK
		URG
		ECE
		CWR
	)

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var decoded []byte
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		decoded = parseHeader(line)
		if decoded == nil {
			continue
		} else {
			break
		}
	}
	flags := decoded
	var flagNames []string
	for i := 0; i < len(flags); i++ {
		if flags[i]&FIN != 0 {
			flagNames = append(flagNames, "FIN")
		}
		if flags[i]&SYN != 0 {
			flagNames = append(flagNames, "SYN")
		}
		if flags[i]&RST != 0 {
			flagNames = append(flagNames, "RST")
		}
		if flags[i]&PSH != 0 {
			flagNames = append(flagNames, "PSH")
		}
		if flags[i]&ACK != 0 {
			flagNames = append(flagNames, "ACK")
		}
		if flags[i]&URG != 0 {
			flagNames = append(flagNames, "URG")
		}
		if flags[i]&ECE != 0 {
			flagNames = append(flagNames, "ECE")
		}
		if flags[i]&CWR != 0 {
			flagNames = append(flagNames, "CWR")
		}
		if flags[i] == 0 {
			flagNames = append(flagNames, "NONE")
		}
	}

	fmt.Println(strings.Join(flagNames, ","))
}

// tep 2 of 5 · Exercise, graded on the executor
//
// Handshake Trace
// Trace one side of a TCP three-way handshake.
//
// Each input line begins with CLIENT or SERVER, followed by a sequence of events to apply in order:
//
// Client side (RFC 793 §3.4):
//
// Starts in INITIAL.
// SEND_SYN while INITIAL → SYN_SENT.
// RECV_SYNACK while SYN_SENT → ESTABLISHED (and the client implicitly sends ACK).
// Server side:
//
// Starts in LISTEN.
// RECV_SYN while LISTEN → SYN_RCVD (and the server replies SYN+ACK).
// RECV_ACK while SYN_RCVD → ESTABLISHED.
// After processing each line, print the final state as client_state=<S> or server_state=<S>.
//
// Example:
//
// INPUT:  CLIENT SEND_SYN RECV_SYNACK
// OUTPUT: client_state=ESTABLISHED
//
// AI Assistant
func handshakeTrace() {
	clientState := "INITIAL"
	serverState := "LISTEN"
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "CLIENT":
			for i := 1; i < len(parts); i++ {
				switch parts[i] {
				case "SEND_SYN":
					clientState = "SYN_SENT"
				case "RECV_SYNACK":
					clientState = "ESTABLISHED"
				}

			}
			fmt.Printf("client_state=%s\n", clientState)
		case "SERVER":
			for i := 1; i < len(parts); i++ {
				switch parts[i] {
				case "RECV_SYN":
					serverState = "SYN_RCVD"

				case "RECV_ACK":
					serverState = "ESTABLISHED"
				}

			}
			fmt.Printf("server_state=%s\n", serverState)
		default:
			fmt.Println("Unknown command")
		}
	}

}

// Step 2 of 5 · Exercise, graded on the executor
//
// Window Bytes In Flight
// Track bytes in flight on a TCP sender.
//
// Bytes in flight = total bytes sent - total bytes cumulatively acknowledged. Both counters start at zero.
//
// Input commands, one per line:
//
// SEND <n> - the sender transmits n more bytes. No output.
// ACK <n> - the peer acknowledges n more bytes. These accumulate; n is a count, not an absolute sequence number. No output.
// INFLIGHT - print the current bytes in flight.
// Only INFLIGHT produces output, one number per line.
//
// Example input:
//
// SEND 100
// INFLIGHT
// ACK 50
// INFLIGHT
// SEND 30
// INFLIGHT
// Expected output:
//
// 100
// 50
// 80
func windowBytesInFlight() {
	bytesSent := 0
	bytesAcked := 0
	bytesInFlight := 0
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line == "INFLIGHT" {
			fmt.Println(bytesInFlight)
		} else {
			parts := strings.Split(line, " ")
			switch parts[0] {
			case "SEND":
				intVal, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Println(err)
				}
				bytesSent += intVal
			case "ACK":
				intVal, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Println(err)
				}
				bytesAcked += intVal
			}
			bytesInFlight = bytesSent - bytesAcked
		}
	}
}

// Step 2 of 5 · Exercise, graded on the executor
//
// EWMA RTT
// Compute the smoothed round-trip-time estimate using Jacobson/Karels (RFC 6298).
//
// Input: RTT <ms> per line (sample float, in milliseconds).
//
// For the first sample: srtt = sample.
//
// For each subsequent sample (alpha = 1/8):
//
// srtt = (1 - alpha) * srtt + alpha * sample
// Output srtt formatted with 4 decimal places after each sample.
//
// Example:
//
// INPUT:        OUTPUT:
// RTT 100       100.0000
// RTT 100       100.0000
// RTT 200       112.5000
func ewmaRTT() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	srtt := 0.0
	alpha := 0.125
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		floatVal, err := strconv.ParseFloat(parts[1], 64)
		if srtt == 0 {
			srtt = floatVal
		} else {
			srtt = (1-alpha)*srtt + alpha*floatVal
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("%.4f\n", srtt)
	}
}

// Step 2 of 5 · Exercise, graded on the executor
//
// TCP Cumulative ACK Queue
// Maintain a TCP sender's retransmission queue under cumulative ACKs (RFC 793 §3.3). Read commands from stdin, one per line:
//
// SEND <seq> <len> — you just sent bytes [seq, seq+len). Append this interval to the outstanding list.
// ACK <ack_no> — the peer cumulatively acknowledges every byte below ack_no. Drop any fully-acked interval; trim the leading edge of a partially-acked one to [ack_no, end).
// QUEUE — print the outstanding intervals as <seq>-<end> items separated by single spaces, or EMPTY if there are none.
// Only QUEUE produces output.
//
// Example input:
//
// SEND 0 100
// SEND 100 100
// ACK 100
// QUEUE
// ACK 200
// QUEUE
// Expected output:
//
// 100-200
// EMPTY
// The starter parses each line and gives you the outstanding list. Watch the partial-ack case: an ACK landing inside an interval trims it — do not drop the whole segment when only its leading edge was acknowledged.
func tcpCumulativeACKQueue() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var outstanding [][2]int
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "SEND":
			seq, _ := strconv.Atoi(parts[1])
			length, _ := strconv.Atoi(parts[2])
			outstanding = append(outstanding, [2]int{seq, seq + length})
		case "ACK":
			ack, _ := strconv.Atoi(parts[1])

			var remaining [][2]int

			for _, interval := range outstanding {
				start := interval[0]
				end := interval[1]

				if ack >= end {
					continue
				}

				if ack > start {
					start = ack
				}

				remaining = append(remaining, [2]int{start, end})
			}
			outstanding = remaining
		case "QUEUE":
			if len(outstanding) == 0 {
				fmt.Println("EMPTY")
			} else {
				var values string
				for _, interval := range outstanding {
					val := fmt.Sprintf("%d-%d", interval[0], interval[1])
					values = values + " " + val
				}
				fmt.Println(strings.TrimSpace(values))
			}
		}
	}
}

// Step 2 of 5 · Exercise, graded on the executor
//
// Slow Start
// Simulate TCP slow start + congestion avoidance (RFC 5681).
//
// Initial state: cwnd = 1.0, ssthresh = 64.
//
// Per input line:
//
// ACK — apply ACK:
// If cwnd < ssthresh (slow start): cwnd += 1.
// Else (congestion avoidance): cwnd += 1 / cwnd.
// Emit cwnd=<x> formatted to 4 decimal places.
// LOSS — multiplicative decrease:
// ssthresh = max(2, floor(cwnd / 2)).
// cwnd = 1.
// Emit loss: cwnd=1 ssthresh=<n>.
// Example:
//
// INPUT:        OUTPUT:
// ACK           cwnd=2.0000
// ACK           cwnd=3.0000
// LOSS          loss: cwnd=1 ssthresh=2
// ACK           cwnd=2.0000
func slowStart() {
	cwnd := 1.0
	ssthresh := 64.0
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch line {
		case "ACK":
			if cwnd < ssthresh {
				cwnd += 1
			} else {
				cwnd += 1 / cwnd
			}
			fmt.Printf("cwnd=%.4f\n", cwnd)
		case "LOSS":
			ssthresh = math.Max(2, math.Floor(cwnd/2))
			cwnd = 1
			fmt.Printf("loss: cwnd=%d ssthresh=%d\n", int(cwnd), int(ssthresh))
		default:
			fmt.Println("Unknown command")
		}
	}
}

// Connection Lifetime
// Simulate a partial TCP connection state machine (RFC 793 §3.2).
//
// State starts at CLOSED. Each input line is either EVENT <name> (apply transition) or STATE (emit current state without changing it).
//
// Transitions:
//
// from	event	to
// CLOSED	active_open	SYN_SENT
// SYN_SENT	recv_synack	ESTABLISHED
// CLOSED	passive_open	LISTEN
// LISTEN	recv_syn	SYN_RCVD
// SYN_RCVD	recv_ack	ESTABLISHED
// ESTABLISHED	close	FIN_WAIT_1
// FIN_WAIT_1	recv_ack	FIN_WAIT_2
// FIN_WAIT_2	recv_fin	TIME_WAIT
// TIME_WAIT	timeout	CLOSED
// ESTABLISHED	recv_fin	CLOSE_WAIT
// CLOSE_WAIT	close	LAST_ACK
// LAST_ACK	recv_ack	CLOSED
// Unknown (state, event) pairs stay in the current state.
//
// Print state after each event/state line.
func connectionLifetime() {
	type TCPState string
	const (
		CLOSED      TCPState = "CLOSED"
		LISTEN      TCPState = "LISTEN"
		SYN_SENT    TCPState = "SYN_SENT"
		SYN_RCVD    TCPState = "SYN_RCVD"
		ESTABLISHED TCPState = "ESTABLISHED"
		FIN_WAIT_1  TCPState = "FIN_WAIT_1"
		FIN_WAIT_2  TCPState = "FIN_WAIT_2"
		CLOSE_WAIT  TCPState = "CLOSE_WAIT"
		LAST_ACK    TCPState = "LAST_ACK"
		TIME_WAIT   TCPState = "TIME_WAIT"
	)
	var transitions = map[TCPState]map[string]TCPState{
		ESTABLISHED: {
			"recv_fin": CLOSE_WAIT,
			"close":    FIN_WAIT_1,
		},

		FIN_WAIT_1: {
			"recv_ack": FIN_WAIT_2,
		},

		FIN_WAIT_2: {
			"recv_fin": TIME_WAIT,
		},
		CLOSE_WAIT: {
			"close": LAST_ACK,
		},
		LAST_ACK: {
			"recv_ack": CLOSED,
		},
		TIME_WAIT: {
			"timeout": CLOSED,
		},
		SYN_SENT: {
			"recv_synack": ESTABLISHED,
		},
		SYN_RCVD: {
			"recv_ack": ESTABLISHED,
		},
		LISTEN: {
			"active_open":  SYN_SENT,
			"passive_open": LISTEN,
			"recv_syn":     SYN_RCVD,
		},
		CLOSED: {
			"active_open":  SYN_SENT,
			"passive_open": LISTEN,
		},
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	state := CLOSED
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "EVENT":
			event := parts[1]
			if transitions[state][event] == "" {
			} else {
				state = transitions[state][event]
			}
			fmt.Println(state)
		case "STATE":
			fmt.Println(state)
		}
	}
}

// Step 2 of 5 · Exercise, graded on the executor
//
// TCP Teardown State Machine
// Drive the TCP teardown state machine for one side of a connection. Start in ESTABLISHED.
//
// Transitions (RFC 793 §3.5):
//
// from	event	to
// ESTABLISHED	close	FIN_WAIT_1
// ESTABLISHED	recv_fin	CLOSE_WAIT
// FIN_WAIT_1	recv_ack	FIN_WAIT_2
// FIN_WAIT_1	recv_fin	CLOSING
// FIN_WAIT_2	recv_fin	TIME_WAIT
// CLOSING	recv_ack	TIME_WAIT
// TIME_WAIT	timeout	CLOSED
// CLOSE_WAIT	close	LAST_ACK
// LAST_ACK	recv_ack	CLOSED
// Inputs:
//
// EVENT <name> — apply transition (unknown pair stays in the current state).
// STATE — print current state without changing it.
// Print state after each line.
//
// Example:
//
// INPUT:                  OUTPUT:
// EVENT close             FIN_WAIT_1
// EVENT recv_ack          FIN_WAIT_2
// EVENT recv_fin          TIME_WAIT
// EVENT timeout           CLOSED
// STATE                   CLOSED
func tcpTeardown() {
	type TCPState string
	const (
		ESTABLISHED TCPState = "ESTABLISHED"
		FIN_WAIT_1  TCPState = "FIN_WAIT_1"
		FIN_WAIT_2  TCPState = "FIN_WAIT_2"
		CLOSING     TCPState = "CLOSING"
		CLOSE_WAIT  TCPState = "CLOSE_WAIT"
		LAST_ACK    TCPState = "LAST_ACK"
		TIME_WAIT   TCPState = "TIME_WAIT"
		CLOSED      TCPState = "CLOSED"
	)
	var transitions = map[TCPState]map[string]TCPState{
		ESTABLISHED: {
			"close":    FIN_WAIT_1,
			"recv_fin": CLOSE_WAIT,
		},
		FIN_WAIT_1: {
			"recv_ack": FIN_WAIT_2,
			"recv_fin": CLOSING,
		},
		FIN_WAIT_2: {
			"recv_fin": TIME_WAIT,
		},
		CLOSING: {
			"recv_ack": TIME_WAIT,
		},
		TIME_WAIT: {
			"timeout": CLOSED,
		},
		CLOSE_WAIT: {
			"close": LAST_ACK,
		},
		LAST_ACK: {
			"recv_ack": CLOSED,
		},
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	state := ESTABLISHED
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "EVENT":
			event := parts[1]
			if transitions[state][event] == "" {
			} else {
				state = transitions[state][event]
			}
			fmt.Println(state)
		case "STATE":
			fmt.Println(state)
		}
	}
}
func main() {
	tcpTeardown()
}

const (
	IPv4 = 0x0800
	IPv6 = 0x86DD
	ARP  = 0x0806
	TCP  = 6
	UDP  = 17
	ICMP = 1
)

// Step 2 of 5 · Exercise, graded on the executor
//
// Decapsulate
// Strip protocol layers from a hex-encoded Ethernet frame and name the layers you peeled.
//
// Input: one hex-encoded frame per line. For each input line print exactly one output line: the chain of layer names you decoded, outermost first, joined with /.
//
// Apply the rules in order:
//
// Ethernet II (RFC 894). The first 14 bytes are a 6-byte destination MAC, a 6-byte source MAC, and a 2-byte big-endian EtherType. Branch on the EtherType:
// 0x0800 (IPv4) - begin the chain with ETH and go on to step 2.
// 0x0806 (ARP) - print ETH/ARP and stop. ARP carries no IP header to peel.
// 0x86DD (IPv6) - print ETH+IPv6 and stop. This course does not decode IPv6 headers.
// anything else - print an empty line.
// IPv4 (RFC 791). Byte 14 of the frame is the first byte of the IPv4 header. Its high nibble is the version and its low nibble is IHL, the header length in 32-bit words. If the version is 4, append IPv4; otherwise stop with just ETH.
// Transport. The Protocol field sits at offset 9 within the IPv4 header. Append the name it selects: 6 -> TCP, 17 -> UDP, 1 -> ICMP. For any other value, stop after IPv4.
// Example:
//
// INPUT:  ffffffffffff001122334455080045000020000100004011a4470a0000010a000002
// OUTPUT: ETH/IPv4/UDP
// EtherType 0800, then version nibble 4, then Protocol 0x11 = 17.
//
// References: RFC 894 (Ethernet II encapsulation), RFC 791 (IPv4), RFC 826 (ARP).
//
// AI Assistant
func parseFrame() {
	eth := "ETH"
	size := 1024 * 1024
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, size), size)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}

		frame := parseHeader(line)
		// fmt.Println(frame)
		// sourceMAC := frame[:5]
		// destinationMAC := frame[5:11]
		etherType := frame[12:14]
		val := binary.BigEndian.Uint16(etherType)

		switch val {
		case IPv4:
			ipv4Header := frame[14]
			version := ipv4Header >> 4
			// ihl := ipv4Header & 0x0F
			if version == 4 {
				typ := "IPv4"
				var protocol string
				readB := int(frame[14+9])
				switch readB {
				case TCP:
					protocol = "TCP"
				case UDP:
					protocol = "UDP"
				case ICMP:
					protocol = "ICMP"
				default:
					fmt.Println(fmt.Sprintf("%s/%s", eth, typ))
					continue
				}
				fmt.Println(fmt.Sprintf("%s/%s/%s", eth, typ, protocol))
				continue
			} else {
				fmt.Println(fmt.Sprintf("%s/%s", eth))
				continue
			}

		case IPv6:
			fmt.Println(fmt.Sprintf("%s+%s", eth, "IPv6"))
			continue
		case ARP:
			fmt.Println(fmt.Sprintf("%s/%s", eth, "ARP"))
			continue
		default:
			fmt.Println("")
		}
	}
}
