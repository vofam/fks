package main

import (
	"github.com/miekg/dns"
	"strings"
)

// Create skeleton edns opt RR from the query and
// add it to the message m
func ednsFromRequest(req, m *dns.Msg) {
	for _, r := range req.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			m.SetEdns0(4096, r.(*dns.RR_OPT).Do())
			return
		}
	}
	return
}

func answer(w dns.ResponseWriter, m, req *dns.Msg, answer []dns.RR, z *dns.Zone) {
	m.SetReply(req)
	m.MsgHdr.Authoritative = true
	m.Answer = answer
	findApex(m, z)
	ednsFromRequest(req, m)
	w.Write(m)
	return
}

func nameerror(w dns.ResponseWriter, m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeNameError)
	ednsFromRequest(req, m)
	w.Write(m)
}

func findGlue(m *dns.Msg, z *dns.Zone, nameserver string) {
	glue, ok := z.Find(nameserver)
	if ok {
		if a4, ok := glue.RR[dns.TypeAAAA]; ok {
			m.Extra = append(m.Extra, a4...)
			return
		}
		if a, ok := glue.RR[dns.TypeA]; ok {
			m.Extra = append(m.Extra, a...)
			return
		}
	}
	// length or the returned packet! TODO(mg)
	return
}

func findApex(m *dns.Msg, z *dns.Zone) {
	apex, exact := z.Find(z.Origin)
	if exact {
		// What if we don't have this? TODO(mg)
		m.Ns = apex.RR[dns.TypeSOA]
	}
	return
}

// Handle exact match
func exactMatch(w dns.ResponseWriter, req, m *dns.Msg, z *dns.Zone, node *dns.ZoneData) {
	logPrintf("[zone %s] exact match for %s\n", z.Origin, req.Question[0].Name)
	// If we have NS records for this name we still need to give out a referral
	if nss, ok := node.RR[dns.TypeNS]; ok && node.NonAuth {
		m.SetReply(req)
		m.Ns = nss
		for _, n := range m.Ns {
			if dns.IsSubDomain(n.(*dns.RR_NS).Ns, n.Header().Name) {
				findGlue(m, z, n.(*dns.RR_NS).Ns)
			}
		}
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}
	// If we have the actual type too
	if rrs, ok := node.RR[req.Question[0].Qtype]; ok {
		answer(w, m, req, rrs, z)
		return
	} else { // NoData reply or CNAME
		m.SetReply(req)
		if cname, ok := node.RR[dns.TypeCNAME]; ok {
			m.Answer = cname
			/*
				i  := 0
				for cname.Rrtype == dns.TypeCNAME {


				}
			*/
			// Lookup cname.Target
			// get cname RRssss

		}
		findApex(m, z)
		w.Write(m)
		return
	}
	nameerror(w, m, req)
	return
}

func serve(w dns.ResponseWriter, req *dns.Msg, z *dns.Zone) {
	if z == nil {
		panic("fksd: no zone")
	}

	m := new(dns.Msg)
	// Just NACK ANYs
	if req.Question[0].Qtype == dns.TypeANY {
		m.SetRcode(req, dns.RcodeServerFailure)
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}

	logPrintf("[zone %s] incoming %s %s %d from %s\n", z.Origin, req.Question[0].Name, dns.Rr_str[req.Question[0].Qtype], req.MsgHdr.Id, w.RemoteAddr())
	node, exact, ref := z.FindFunc(req.Question[0].Name, func(n interface{}) bool {
		return n.(*dns.ZoneData).NonAuth
	})
	if ref {
		logPrintf("[zone %s] referral due\n", z.Origin)
		m.SetReply(req)
		m.Ns = node.RR[dns.TypeNS]
		for _, n := range m.Ns {
			if dns.IsSubDomain(n.(*dns.RR_NS).Ns, n.Header().Name) {
				findGlue(m, z, n.(*dns.RR_NS).Ns)
			}
		}
		ednsFromRequest(req, m)
		w.Write(m)
		return
	}
	if exact {
		exactMatch(w, req, m, z, node)
	}
	// Not an exact match nor an referral

	if z.Wildcard > 0 {
		lx := dns.SplitLabels(req.Question[0].Name)
		wc := "*." + strings.Join(lx[1:], ".")
		node, exact = z.Find(wc)
		if exact {
			logPrintf("[zone %s] wildcard answer\n", z.Origin)
			// as exact,but not complete -- only the last part
		}
	}
	nameerror(w, m, req)
	return
}
