package main

import (
	"flag"
	"github.com/miekg/dns"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
)

var (
	flaglog   = flag.Bool("log", false, "log incoming queries")
	flagprof  = flag.String("prof", "", "write cpu profile to file")
	port      = flag.Int("port", 1053, "port to use")
	superuser = flag.String("user", "root", "username to use for the superuser")
	superkey  = flag.String("key", "c3R1cGlk", "base64 tsig key for superuser authentication")
)

func main() {
	flag.Parse()
	if *flagprof != "" {
		f, err := os.Create(*flagprof)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	*superuser = strings.ToLower(*superuser)
	conf := NewConfig()
	conf.Rights[*superuser] = R_LIST | R_WRITE | R_DROP | R_USER // *all* of them

	go func() {
		conf.ServerUDP = &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "udp", TsigSecret: map[string]string{dns.Fqdn(*superuser): *superkey}}
		err := conf.ServerUDP.ListenAndServe()
		if err != nil {
			log.Fatal("fksd: could not start udp listener: %s", err.Error())
		}
	}()
	go func() {
		conf.ServerTCP = &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "tcp", TsigSecret: map[string]string{dns.Fqdn(*superuser): *superkey}}
		err := conf.ServerTCP.ListenAndServe()
		if err != nil {
			log.Fatal("fksd: could not start tcp listener: %s", err.Error())
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
