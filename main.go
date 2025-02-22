package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipfs/go-cid"
	crp "github.com/libp2p/go-libp2p/core/crypto"
	peer "github.com/libp2p/go-libp2p/core/peer"
	mbase "github.com/multiformats/go-multibase"
)

var (
	keys      uint64
	startTime time.Time
)

func main() {
	size := flag.Int("bitsize", 2048, "select the bitsize of the key to generate")
	typ := flag.String("type", "", "select type of key to generate (RSA, Ed25519, Secp256k1 or ECDSA)")
	key := flag.String("key", "", "specify the location of the key to decode it's peerID")
	fast := flag.Bool("fast", false, "fast generate")
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout")
	suff := flag.String("suff", "", "specify suffixes, comma separated, minimum 3 chars")

	flag.Parse()

	if fast != nil && *fast && len(*suff) >= 3 {
		FastGeneration(*timeout, *suff)
		return
	}

	if *key != "" {
		if err := readKey(key, typ); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		return
	}

	if *typ == "" {
		*typ = "ed25519"
	}
	if err := genKey(typ, size); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}
}

func readKey(keyLoc *string, typ *string) error {
	data, err := os.ReadFile(*keyLoc)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "Reading key at: %s\n", *keyLoc)

	var unmarshalPrivateKeyFucn func(data []byte) (crp.PrivKey, error)
	// rsa and ed25519 unmarshalPrivateKeyFucn are for backward compatibility
	// for keys saved with raw(), to read such keys, specify the key type
	switch strings.ToLower(*typ) {
	case "rsa":
		unmarshalPrivateKeyFucn = crp.UnmarshalRsaPrivateKey
	case "ed25519":
		unmarshalPrivateKeyFucn = crp.UnmarshalEd25519PrivateKey
	default:
		unmarshalPrivateKeyFucn = crp.UnmarshalPrivateKey
	}

	prvk, err := unmarshalPrivateKeyFucn(data)
	if err != nil {
		return err
	}

	id, err := peer.IDFromPrivateKey(prvk)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(
		os.Stderr,
		"Success!\nID for %s key: %s\nPrivate key (base64): %s\n",
		prvk.Type().String(),
		id.String(),
		base64.StdEncoding.EncodeToString(data),
	)

	return err
}

func genKey(typ *string, size *int) error {
	var atyp int
	switch strings.ToLower(*typ) {
	case "rsa":
		atyp = crp.RSA
	case "ed25519":
		atyp = crp.Ed25519
	case "secp256k1":
		atyp = crp.Secp256k1
	case "ecdsa":
		atyp = crp.ECDSA
	default:
		return fmt.Errorf("unrecognized key type: %s", *typ)
	}

	_, _ = fmt.Fprintf(os.Stderr, "Generating a %d bit %s key...\n", *size, *typ)

	priv, pub, err := crp.GenerateKeyPair(atyp, *size)
	if err != nil {
		return err
	}

	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return err
	}

	data, err := crp.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		return nil
	}

	_, err = fmt.Fprintf(
		os.Stderr,
		"Success!\nID for generated key: %s\nPrivate key (base64): %s\n",
		pid.String(),
		base64.StdEncoding.EncodeToString(data),
	)

	return err
}

func saveToFile(data []byte, filePath string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}

	return
}

type Config struct {
	NumWorkers int // Количество рабочих (по умолчанию равно количеству CPU)
	Suffixes   []string
	Timeout    time.Duration // Таймаут для всей операции
}

type Result struct {
	Found     bool
	String    string
	WorkerID  int
	Cancelled bool
}

func NewConfig(suffixes []string, timeout time.Duration) Config {
	return Config{
		NumWorkers: runtime.NumCPU(),
		Suffixes:   suffixes,
		Timeout:    timeout,
	}
}

func worker(ctx context.Context, config Config, id int, resultChan chan Result, cancelFunc func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Worker %d panicked: %v\n", id, r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			resultChan <- Result{Cancelled: true}
			return
		default:
			priv, pub, err := crp.GenerateKeyPair(crp.Ed25519, 2048)
			if err != nil {
				continue
			}

			pid, err := peer.IDFromPublicKey(pub)
			if err != nil {
				continue
			}

			c, err := cid.Decode(peer.ToCid(pid).String())
			if err != nil {
				continue
			}

			privateKeyAsb36, err := c.StringOfBase(mbase.Base36)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				continue
			}

			//haystack := privateKeyAsb36[len(privateKeyAsb36)-15:]
			for _, needle := range config.Suffixes {
				if strings.HasSuffix(privateKeyAsb36, needle) {
					cancelFunc() // Останавливаем все горутины

					_, _ = fmt.Fprintf(
						os.Stdout,
						"ID for generated key: %s\nPKey(base36): %s\n",
						pid.String(),
						privateKeyAsb36,
					)

					data, _ := crp.MarshalPrivateKey(priv)
					saveToFile(data, "private.key")

					resultChan <- Result{
						Found:    true,
						String:   privateKeyAsb36,
						WorkerID: id,
					}
					return
				}
			}

			atomic.AddUint64(&keys, 1)
		}
	}
}

func run(config Config) (*Result, error) {
	ctx, cancel := context.WithCancel(context.Background())

	resultChan := make(chan Result)
	var wg sync.WaitGroup

	startTime = time.Now()
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()
			worker(ctx, config, id, resultChan, cancel)
		}(i)
	}

	// Мониторим результаты и таймаут
	go func() {
		ticker := time.NewTicker(config.Timeout)
		defer ticker.Stop()

		hashrateTicker := time.NewTicker(config.Timeout / 6)
		defer hashrateTicker.Stop()

		for {
			select {
			case <-hashrateTicker.C:
				x := uint64(time.Since(startTime).Milliseconds())
				fmt.Printf("Hash rate: ~%d kHz\n", keys/x)
			case <-ticker.C:
				_, _ = fmt.Printf("Keys generated: %d\n", keys)
				cancel()
				return
			}
		}
	}()

	// Ждем завершения или получения результата
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Получаем первый успешный результат
	for res := range resultChan {
		if !res.Cancelled && res.Found {
			return &res, nil
		}
	}

	return nil, fmt.Errorf("not found")
}

func FastGeneration(timeout time.Duration, suff string) {
	suffixes := strings.Split(strings.TrimSpace(suff), ",")
	config := NewConfig(suffixes, timeout)

	fmt.Printf("Config: %+v\n", config)
	result, err := run(config)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Found: %s\n", result.String)
}
