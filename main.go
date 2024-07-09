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
	secrets   = flag.String("f", "", "file path to the secrets file")
	datefmt   = flag.String("D", "15:04:06", "date format of the next generation")
	digits    = flag.Int("d", 6, "amount of digits in the passwords")
	interval  = flag.Int("i", 30, "delay (in seconds) between each generation")
	once      = flag.Bool("o", false, "generate passwords once")
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
		d      = uint(binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7FFFFFFF)
	)
	return fmt.Sprintf("%0*d", *digits, d%uint(math.Pow10(*digits))), nil
}

func parse(f *os.File) error {
	s := bufio.NewScanner(f)
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
	fmt.Fprintf(os.Stderr, "%s will read from standard input if -f is not specified.\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "File is expected to be tab separated containing the display\nname and the secret itself.\n\n")
	flag.PrintDefaults()
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
		dur = time.Second * time.Duration(*interval)
		t   = time.NewTicker(dur)
	)
	for ; true; <-t.C {
		fmt.Printf("%s - Next in %s\n", time.Now().Format(*datefmt), dur)
		for name, key := range providers {
			decoded, err := base32.StdEncoding.DecodeString(string(key))
			if err != nil {
				fmt.Fprintf(os.Stderr, "base32 decoding failed: %q (%s)\n", err, name)
				decoded = []byte(key)
			}
			secret, err := TOTP(time.Now(), decoded, dur)
			if err != nil {
				fmt.Fprintf(os.Stderr, "totp: %q", err)
				continue
			}
			fmt.Printf("%-25s %s\n", name, secret)
		}
		if *once {
			break
		}
	}
}
