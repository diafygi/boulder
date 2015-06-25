// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

func TestDNSNoServers(t *testing.T) {
	obj := NewDNSResolver(time.Hour, []string{})

	m := new(dns.Msg)
	_, _, err := obj.ExchangeOne(m)

	test.AssertError(t, err, "No servers")
}

func TestDNSOneServer(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53"})

	m := new(dns.Msg)
	m.SetQuestion("letsencrypt.org.", dns.TypeSOA)
	_, _, err := obj.ExchangeOne(m)

	test.AssertNotError(t, err, "No message")
}

func TestDNSDuplicateServers(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53", "8.8.8.8:53"})

	m := new(dns.Msg)
	m.SetQuestion("letsencrypt.org.", dns.TypeSOA)
	_, _, err := obj.ExchangeOne(m)

	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		test.AssertNotError(t, err, "No message")
	}
}

func TestDNSLookupTXT(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53", "8.8.8.8:53"})

	a, rtt, err := obj.LookupTXT("letsencrypt.org")

	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		t.Logf("A: %v RTT %s", a, rtt)
		test.AssertNotError(t, err, "No message")
	}
}

func TestDNSLookupTXTNoServer(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{})

	_, _, err := obj.LookupTXT("letsencrypt.org")
	test.AssertError(t, err, "No servers")
}

func TestDNSSEC(t *testing.T) {
	goodServer := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53"})

	badSig := "www.dnssec-failed.org"

	_, _, err := goodServer.LookupTXT(badSig)
	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		test.AssertError(t, err, "LookupTXT didn't return an error")
	}

	_, err = goodServer.LookupCNAME(badSig)
	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		test.AssertError(t, err, "LookupCNAME didn't return an error")
	}

	// XXX: CAA lookup ignores validation failures from the resolver for now
	_, err = goodServer.LookupCAA(badSig, false)
	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		test.AssertNotError(t, err, "LookupCAA returned an error")
	}

	goodSig := "sigok.verteiltesysteme.net"

	_, _, err = goodServer.LookupTXT(goodSig)
	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		test.AssertNotError(t, err, "LookupTXT returned an error")
	}

	_, err = goodServer.LookupCNAME(goodSig)
	// XXX: Until #401 is resolved ignore DNS timeouts
	if err == nil || err != nil && err.Error() != "read udp 8.8.8.8:53: i/o timeout" {
		test.AssertNotError(t, err, "LookupCNAME returned an error")
	}

	badServer := NewDNSResolver(time.Second*10, []string{"127.0.0.1:99"})

	_, _, err = badServer.LookupTXT(goodSig)
	test.AssertError(t, err, "LookupTXT didn't return an error")

	_, err = badServer.LookupCNAME(goodSig)
	test.AssertError(t, err, "LookupCNAME didn't return an error")

	_, err = badServer.LookupCAA(goodSig, false)
	test.AssertError(t, err, "LookupCAA didn't return an error")
}
