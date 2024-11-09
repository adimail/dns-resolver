//   ____  _   _ ____    ____  _____ ____   ___  _ __     _______ ____
//  |  _ \| \ | / ___|  |  _ \| ____/ ___| / _ \| |\ \   / / ____|  _ \
//  | | | |  \| \___ \  | |_) |  _| \___ \| | | | | \ \ / /|  _| | |_) |
//  | |_| | |\  |___) | |  _ <| |___ ___) | |_| | |__\ V / | |___|  _ <
//  |____/|_| \_|____/  |_| \_\_____|____/ \___/|_____\_/  |_____|_| \_\
//

// The Domain Name System (DNS) translates human-readable domain names (like google.com)
// into machine-readable IP addresses (like 142.250.190.78).
//
// When a user tries to visit a website,
// their computer queries a DNS server to resolve the domain name to an IP address.

// Major Components of DNS:
// DNS Header: Contains metadata about the query, such as ID, flags, and counts of questions, answers, and additional records.
// DNS Question Section: Specifies the domain name, type (e.g., A, CNAME), and class of the query.
// DNS Answer Section: Contains resolved information (e.g., IP address for an A record).
// DNS Cache: Caches results to improve performance and reduce latency.

// Record Types:
// A: Maps a domain to an IPv4 address.
// NS: Identifies authoritative name servers.
// CNAME: Represents an alias for another domain.
// SOA: Contains administrative information about a zone.
// MX: Specifies mail exchange servers for a domain.

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// DNS Header format
type DNSHeader struct {
	ID      uint16 // Unique identifier for the query
	Flags   uint16 // Flags to indicate query/response type
	QDCount uint16 // Number of questions
	ANCount uint16 // Number of answers
	NSCount uint16 // Number of authoritative name server records
	ARCount uint16 // Number of additional records
}

// DNS Question format
// This specifies the query details: the domain name, query type (e.g., A, MX), and class (usually IN for Internet).
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNS Resource Record
// This represents the data returned in response to a DNS query, including the resolved IP address or other data.
type DNSRecord struct {
	Name     string    // Domain name
	Type     uint16    // Record type (e.g., A, NS)
	Class    uint16    // Record class (e.g., IN)
	TTL      uint32    // Time to live (in seconds)
	RDLength uint16    // Length of the RData field
	RData    string    // Resource data (e.g., IP address)
	ExpireAt time.Time // When the record should expire (computed from TTL)
}

// Cache to store DNS records
type DNSCache struct {
	records map[string]DNSRecord
	mutex   sync.RWMutex
}

// Constants for DNS record types
const (
	TypeA     = 1  // Address record
	TypeNS    = 2  // Nameserver
	TypeCNAME = 5  // Canonical name
	TypeSOA   = 6  // Start of authority
	TypeMX    = 15 // Mail exchange
)

// Create new cache
func NewDNSCache() *DNSCache {
	return &DNSCache{
		records: make(map[string]DNSRecord),
	}
}

// Add record to cache
func (c *DNSCache) Add(key string, record DNSRecord) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	record.ExpireAt = time.Now().Add(time.Duration(record.TTL) * time.Second)
	c.records[key] = record
	log.Printf("Added record to cache: %s", key)
}

// Get record from cache
func (c *DNSCache) Get(key string) (DNSRecord, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	record, exists := c.records[key]
	if !exists {
		return DNSRecord{}, false
	}

	// Check if record has expired
	if time.Now().After(record.ExpireAt) {
		delete(c.records, key)
		return DNSRecord{}, false
	}

	log.Printf("Cache hit for: %s", key)
	return record, true
}

// DNS Server struct
type DNSServer struct {
	cache *DNSCache
	conn  *net.UDPConn
}

// Create new DNS server
func NewDNSServer() *DNSServer {
	return &DNSServer{
		cache: NewDNSCache(),
	}
}

// Start DNS server
func (s *DNSServer) Start(port int) error {
	addr := &net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("127.0.0.1"),
	}

	var err error
	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP server: %v", err)
	}

	log.Printf("DNS Server listening on 127.0.0.1:%d", port)

	// Handle incoming requests
	for {
		buf := make([]byte, 512) // DNS messages are typically limited to 512 bytes
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		log.Printf("Received %d bytes from %s", n, remoteAddr.String())
		go s.handleQuery(buf[:n], remoteAddr)
	}
}

// Handle DNS query
func (s *DNSServer) handleQuery(query []byte, remoteAddr *net.UDPAddr) {
	// Parse DNS header
	if len(query) < 12 {
		log.Printf("Query too short")
		return
	}

	header := &DNSHeader{
		ID:      binary.BigEndian.Uint16(query[0:2]),
		Flags:   binary.BigEndian.Uint16(query[2:4]),
		QDCount: binary.BigEndian.Uint16(query[4:6]),
		ANCount: binary.BigEndian.Uint16(query[6:8]),
		NSCount: binary.BigEndian.Uint16(query[8:10]),
		ARCount: binary.BigEndian.Uint16(query[10:12]),
	}

	log.Printf("Received DNS query with ID: %d", header.ID)

	// Parse question section
	offset := 12
	questions := make([]DNSQuestion, header.QDCount)
	for i := uint16(0); i < header.QDCount; i++ {
		name, newOffset := parseDomainName(query, offset)
		qType := binary.BigEndian.Uint16(query[newOffset : newOffset+2])
		qClass := binary.BigEndian.Uint16(query[newOffset+2 : newOffset+4])

		questions[i] = DNSQuestion{
			Name:  name,
			Type:  qType,
			Class: qClass,
		}
		offset = newOffset + 4

		log.Printf("Question: %s (Type: %d, Class: %d)", name, qType, qClass)
	}

	// Check cache first
	if record, found := s.cache.Get(questions[0].Name); found {
		log.Printf("Found in cache: %s", questions[0].Name)
		// Send cached response
		response := s.createResponse(header, questions[0], record)
		s.conn.WriteToUDP(response, remoteAddr)
		return
	}

	log.Printf("Cache miss for: %s", questions[0].Name)

	// If not in cache, forward to upstream DNS server
	upstreamResponse := s.queryUpstream(questions[0])
	if upstreamResponse != nil {
		// Cache the response
		s.cache.Add(questions[0].Name, *upstreamResponse)
		// Send response to client
		response := s.createResponse(header, questions[0], *upstreamResponse)
		s.conn.WriteToUDP(response, remoteAddr)
		log.Printf("Sent response for: %s", questions[0].Name)
	}
}

// Parse domain name from DNS message
func parseDomainName(query []byte, offset int) (string, int) {
	var name string
	var length int

	for {
		length = int(query[offset])
		if length == 0 {
			break
		}
		if name != "" {
			name += "."
		}
		name += string(query[offset+1 : offset+1+length])
		offset += length + 1
	}

	return name, offset + 1
}

// Convert domain name to DNS wire format
func encodeDomainName(domain string) []byte {
	var encoded []byte
	labels := strings.Split(domain, ".")

	for _, label := range labels {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}

	// Add terminating zero
	encoded = append(encoded, 0)
	return encoded
}

// Create DNS response
func (s *DNSServer) createResponse(header *DNSHeader, question DNSQuestion, record DNSRecord) []byte {
	response := make([]byte, 0, 512) // Start with empty slice

	// 1. Header (12 bytes)
	headerBytes := make([]byte, 12)
	binary.BigEndian.PutUint16(headerBytes[0:2], header.ID) // Query ID
	binary.BigEndian.PutUint16(headerBytes[2:4], 0x8180)    // Flags: Standard response + Recursion Available
	binary.BigEndian.PutUint16(headerBytes[4:6], 1)         // Questions count
	binary.BigEndian.PutUint16(headerBytes[6:8], 1)         // Answer count
	binary.BigEndian.PutUint16(headerBytes[8:10], 0)        // Authority count
	binary.BigEndian.PutUint16(headerBytes[10:12], 0)       // Additional count
	response = append(response, headerBytes...)

	// 2. Question section
	// Domain name in DNS wire format
	response = append(response, encodeDomainName(question.Name)...)

	// Question type and class
	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], question.Type)
	binary.BigEndian.PutUint16(typeClass[2:4], question.Class)
	response = append(response, typeClass...)

	// 3. Answer section
	// Name pointer (compression) - points to the name in the question section
	response = append(response, 0xC0, 0x0C) // Standard pointer to question name

	// Type, Class, TTL, and RDLength
	answerMetadata := make([]byte, 8)
	binary.BigEndian.PutUint16(answerMetadata[0:2], record.Type)
	binary.BigEndian.PutUint16(answerMetadata[2:4], record.Class)
	binary.BigEndian.PutUint32(answerMetadata[4:8], record.TTL)
	response = append(response, answerMetadata...)

	// For A record (IPv4 address)
	if record.Type == TypeA {
		// Convert IP string to 4 bytes
		ip := net.ParseIP(record.RData)
		if ip != nil {
			ipv4 := ip.To4()
			if ipv4 != nil {
				binary.BigEndian.PutUint16(answerMetadata[0:2], uint16(len(ipv4))) // RDLength
				response = append(response, answerMetadata[0:2]...)
				response = append(response, ipv4...)
			}
		}
	}

	return response
}

// Query upstream DNS server
func (s *DNSServer) queryUpstream(question DNSQuestion) *DNSRecord {
	log.Printf("Querying upstream for: %s", question.Name)

	// For testing, return a fixed IP address
	// In a real implementation, this would query an upstream DNS server
	// THIS IS DUMMY DATA
	// In next update I will implement the `miekg/dns` DNS upstream DNS server
	return &DNSRecord{
		Name:     question.Name,
		Type:     TypeA,
		Class:    1,
		TTL:      300,
		RDLength: 4,
		RData:    "93.184.216.34",
	}
}

func main() {
	server := NewDNSServer()
	port := 5300
	log.Printf("Starting DNS server on port %d...", port)
	err := server.Start(port)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
