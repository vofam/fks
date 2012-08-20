package main

import (
	"github.com/miekg/dns"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
)

var (
	flaglog   = flag.Bool("log", false, "log incoming queries")
	port = flag.Int("port", 1035, "port to use")
	superuser = flag.String("user", "root", "username to use for the superuser")
	superkey  = flag.String("key", "c3R1cGlk", "base64 tsig key for superuser authentication")
)

func main() {
	flag.Parse()
	*superuser = strings.ToLower(*superuser)
	conf := NewConfig()
	conf.Rights[*superuser] = R_LIST | R_WRITE | R_DROP | R_USER // *all* of them

	go func() {
		conf.ServerUDP = &dns.Server{Addr: ":" + strconv.Itoa(*port) , Net: "tcp", TsigSecret: map[string]string{dns.Fqdn(*superuser): *superkey}}
		err := conf.ServerUDP.ListenAndServe()
		if err != nil {
			log.Fatal("fksd: could not start config listener: %s", err.Error())
		}
	}()
	go func() {
		conf.ServerTCP = &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "tcp", TsigSecret: map[string]string{dns.Fqdn(*superuser): *superkey}}
		err := conf.ServerTCP.ListenAndServe()
		if err != nil {
			log.Fatal("fksd: could not start config listener: %s", err.Error())
		}
	}()

	// Hijack these zone names, but only if they use the CLASS 65516
	dns.HandleFunc("zone.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })
	dns.HandleFunc("user.", func(w dns.ResponseWriter, req *dns.Msg) { config(w, req, conf) })

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
forever:
	for {
		select {
		case <-sig:
			logPrintf("signal received, stopping")
			break forever
		}
	}
}
