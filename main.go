// Command totp implements a TOTP authenticator as specified by RFC6238.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	providers = make(map[string]string)
	secrets   = flag.String("f", "", "file path to a secrets file (if any)")
	datefmt   = flag.String("D", "15:04:06", "date format of the next key generation")
	digits    = flag.Int("d", 6, "amount of digits")
)

// TOTP generates a time-based one-time password (TOTP).
func TOTP(when time.Time, key []byte, interval time.Duration) (string, error) {
	var (
		hash = hmac.New(sha1.New, key)
		buf  = make([]byte, 8)
		now  = uint64(when.Unix() / int64(interval.Seconds()))
	)
	binary.BigEndian.PutUint64(buf, now)
	if _, err := hash.Write(buf); err != nil {
		return "", err
	}
	var (
		mac    = hash.Sum(nil)
		offset = mac[len(mac)-1] & 0xF
	)
	return fmt.Sprintf("%0*d", *digits, uint(binary.BigEndian.Uint32(mac[offset:offset+4])&0x7FFFFFFF) % uint(math.Pow10(*digits))), nil
}

func parse(f *os.File) error {
	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		parts := strings.Split(s.Text(), "\t")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid line: %q, ignoring\n", s.Text())
			continue
		}
		providers[parts[0]] = parts[1]
	}
	if err := s.Err(); err != nil {
		return err
	}
	if len(providers) < 1 {
		return fmt.Errorf("invalid data provided")
	}
	return nil
}

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s [-f file] [-d digits] [-D date format]\n\n", prog)
	fmt.Fprintf(os.Stderr, "If the -f flag is not been specified, %s will read from standard input.\n", prog)
	fmt.Fprintf(os.Stderr, "%s expects data that is TAB separated and it needs contain two fields,\n", prog)
	fmt.Fprintf(os.Stderr, "the first field is a display name for the service, the other is the secret key.\n\n")
	os.Exit(1)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	var f = os.Stdin
	if *secrets != "" {
		var err error
		f, err = os.Open(*secrets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open: %s\n", err)
			os.Exit(1)
		}
		defer f.Close()
	}
	if err := parse(f); err != nil {
		fmt.Fprintf(os.Stderr, "parse: %s\n", err)
		os.Exit(1)
	}
	var (
		dur = time.Second * 30
		t   = time.NewTicker(dur)
	)
	for ; true; <-t.C {
		fmt.Printf("%s - Next in %s\n", time.Now().Format(*datefmt), dur)
		for n, k := range providers {
			decoded, err := base32.StdEncoding.DecodeString(string(k))
			if err != nil {
				fmt.Fprintf(os.Stderr, "decoding failed: %q (%s)\n", err, n)
				decoded = []byte(k)
			}
			secret, err := TOTP(time.Now(), decoded, time.Duration(time.Second*30))
			if err != nil {
				fmt.Fprintf(os.Stderr, "totp: %q", err)
				continue
			}
			fmt.Printf("%-25s %s\n", n, secret)
		}
	}
}
