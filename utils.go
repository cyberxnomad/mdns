package mdns

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// textToMap parses raw DNS TXT record strings into a key-value map.
//
// DNS TXT records contain a list of strings. According to RFC6763 Section 6.3,
// each string SHOULD be of the form "key=value".
//
// Example:
//
//	[]string{"path=/api", "version=1"} -> map[string]string{"path": "/api", "version": "1"}
func textToMap(txt []string) map[string]string {
	m := make(map[string]string)

	for _, t := range txt {
		k, v, _ := strings.Cut(t, "=")
		if len(k) > 0 {
			m[k] = v
		}
	}

	return m
}

// textToSlice converts a key-value map into DNS TXT record strings.
//
// Each key-value pair is formatted as "key=value". The resulting slice
// can be used directly in a dnsmessage.TXTResource.
//
// Example:
//
//	map[string]string{"path": "/api", "version": "1"} -> []string{"path=/api", "version=1"}
func textToSlice(text map[string]string) []string {
	ss := make([]string, 0, len(text))
	for k, v := range text {
		ss = append(ss, fmt.Sprintf("%s=%s", k, v))
	}

	return ss
}

// decodeDNSMessage parses a raw DNS packet into a dnsmessage.Message.
//
// It follows the standard DNS section order:
//  1. Header
//  2. Questions
//  3. Answers
//  4. Authorities
//  5. Additionals
//
// Returns an error if any section fails to parse.
func decodeDNSMessage(data []byte) (*dnsmessage.Message, error) {
	var err error
	msg := &dnsmessage.Message{}
	parser := dnsmessage.Parser{}

	msg.Header, err = parser.Start(data)
	if err != nil {
		return nil, err
	}

	msg.Questions, err = parser.AllQuestions()
	if err != nil {
		return nil, err
	}

	msg.Answers, err = parser.AllAnswers()
	if err != nil {
		return nil, err
	}

	msg.Authorities, err = parser.AllAuthorities()
	if err != nil {
		return nil, err
	}

	msg.Additionals, err = parser.AllAdditionals()
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// appendNonNil appends non-nil elements from elems to slice.
func appendNonNil[T any](slice []*T, elems ...*T) []*T {
	for _, elem := range elems {
		if elem != nil {
			slice = append(slice, elem)
		}
	}
	return slice
}
