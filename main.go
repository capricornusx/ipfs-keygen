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

	crp "github.com/libp2p/go-libp2p/core/crypto"
	peer "github.com/libp2p/go-libp2p/core/peer"
	mbase "github.com/multiformats/go-multibase"
)

var (
	keys      uint64
	startTime time.Time
)

func main() {
	key := flag.String("key", "", "specify the location of the key to read")
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout for vanity key generation")
	suff := flag.String("suff", "", "comma-separated list of suffixes (min 4 chars each)")

	flag.Parse()

	if *key != "" {
		if err := readKey(key); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *suff != "" {
		FastGeneration(*timeout, *suff)
		return
	}

	_, _ = fmt.Fprintln(os.Stderr, "Usage:")
	_, _ = fmt.Fprintln(os.Stderr, "  Generate vanity key: ipfs-key -suff=test,cool -timeout=1m")
	_, _ = fmt.Fprintln(os.Stderr, "  Read key:            ipfs-key -key keys/test_*.key")
	os.Exit(1)
}

func readKey(keyLoc *string) error {
	data, err := os.ReadFile(*keyLoc)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "Reading key at: %s\n", *keyLoc)

	prvk, err := crp.UnmarshalPrivateKey(data)
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

func saveToFile(data []byte, suffix string) error {
	// Создаём директорию keys если её нет
	if err := os.MkdirAll("keys", 0755); err != nil {
		return err
	}

	// Формируем имя файла: keys/suffix_timestamp.key
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("keys/%s_%s.key", suffix, timestamp)

	// Сохраняем ключ
	if err := os.WriteFile(fileName, data, 0600); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "\n💾 Key saved: %s\n", fileName)
	return nil
}

type Config struct {
	NumWorkers    int
	Suffixes      []string
	SuffixesBytes [][]byte // Предкомпилированные суффиксы в base36
	Timeout       time.Duration
	MaxSuffLen    int
	ActiveSuffixes *sync.Map // Потокобезопасная карта активных суффиксов
}

type Result struct {
	Found     bool
	String    string
	Suffix    string
	WorkerID  int
	Cancelled bool
}

func NewConfig(suffixes []string, timeout time.Duration) Config {
	maxLen := 0
	suffixesBytes := make([][]byte, len(suffixes))
	activeSuffixes := &sync.Map{}
	for i, s := range suffixes {
		if len(s) > maxLen {
			maxLen = len(s)
		}
		suffixesBytes[i] = []byte(s)
		activeSuffixes.Store(s, true)
	}
	return Config{
		NumWorkers:    runtime.NumCPU(),
		Suffixes:      suffixes,
		SuffixesBytes: suffixesBytes,
		Timeout:       timeout,
		MaxSuffLen:    maxLen + 6,
		ActiveSuffixes: activeSuffixes,
	}
}

func worker(ctx context.Context, config Config, id int, resultChan chan Result) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Worker %d panicked: %v\n", id, r)
		}
	}()

	localCounter := uint64(0)
	const batchSize = 10000

	for {
		select {
		case <-ctx.Done():
			atomic.AddUint64(&keys, localCounter)
			return
		default:
		}

		// Генерируем пачку ключей без проверки ctx
		for i := 0; i < 100; i++ {
			priv, pub, err := crp.GenerateKeyPair(crp.Ed25519, 0)
			if err != nil {
				continue
			}

			pid, err := peer.IDFromPublicKey(pub)
			if err != nil {
				continue
			}

			pidStr := pid.String()

			// Проверяем последние символы напрямую
			for _, needle := range config.SuffixesBytes {
				suffix := string(needle)
				// Проверяем, активен ли ещё этот суффикс
				if _, active := config.ActiveSuffixes.Load(suffix); !active {
					continue
				}

				if len(pidStr) >= len(needle) {
					match := true
					offset := len(pidStr) - len(needle)
					for j := 0; j < len(needle); j++ {
						if pidStr[offset+j] != needle[j] {
							match = false
							break
						}
					}
					if match {
						// Пытаемся удалить суффикс (атомарно)
						if _, loaded := config.ActiveSuffixes.LoadAndDelete(suffix); !loaded {
							// Другой воркер уже нашёл этот суффикс
							continue
						}

						atomic.AddUint64(&keys, localCounter)
						localCounter = 0

						c := peer.ToCid(pid)
						privateKeyAsb36, _ := c.StringOfBase(mbase.Base36)

						_, _ = fmt.Fprintf(
							os.Stdout,
							"ID for generated key: %s\nPKey(base36): %s\n",
							pidStr,
							privateKeyAsb36,
						)

						data, _ := crp.MarshalPrivateKey(priv)
						if err := saveToFile(data, suffix); err != nil {
							_, _ = fmt.Fprintf(os.Stderr, "Error saving key: %v\n", err)
						}

						resultChan <- Result{
							Found:    true,
							String:   privateKeyAsb36,
							Suffix:   suffix,
							WorkerID: id,
						}
						break // Переходим к следующему ключу
					}
				}
			}

			localCounter++
		}

		if localCounter%batchSize == 0 {
			atomic.AddUint64(&keys, batchSize)
			localCounter -= batchSize
		}
	}
}

func run(config Config) ([]Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	resultChan := make(chan Result, config.NumWorkers)
	var wg sync.WaitGroup

	startTime = time.Now()
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()
			worker(ctx, config, id, resultChan)
		}(i)
	}

	// Горутина для мониторинга прогресса
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				cnt := atomic.LoadUint64(&keys)
				if elapsed > 0 {
					rate := float64(cnt) / elapsed
					// Подсчитываем оставшиеся суффиксы
					remaining := 0
					config.ActiveSuffixes.Range(func(key, value interface{}) bool {
						remaining++
						return true
					})
					_, _ = fmt.Fprintf(os.Stderr, "[%.0fs] %d keys | %.0f keys/s | %d/%d suffixes remaining\n", 
						elapsed, cnt, rate, remaining, len(config.Suffixes))
				}
			}
		}
	}()

	// Горутина для закрытия канала результатов
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []Result
	for res := range resultChan {
		if res.Found {
			results = append(results, res)
			// Проверяем, все ли суффиксы найдены
			found := 0
			config.ActiveSuffixes.Range(func(key, value interface{}) bool {
				found++
				return true
			})
			if found == 0 {
				// Все суффиксы найдены, останавливаем поиск
				cancel()
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no keys found")
	}

	return results, nil
}

func FastGeneration(timeout time.Duration, suff string) {
	suffixes := strings.Split(strings.TrimSpace(suff), ",")

	// Валидация суффиксов
	for _, s := range suffixes {
		if len(s) < 4 {
			_, _ = fmt.Fprintf(os.Stderr, "Error: suffix '%s' is too short (minimum 4 chars)\n", s)
			os.Exit(1)
		}
	}

	config := NewConfig(suffixes, timeout)

	_, _ = fmt.Fprintf(os.Stderr, "Config: Workers=%d, Suffixes=%v, Timeout=%v\n", config.NumWorkers, config.Suffixes, config.Timeout)
	_, _ = fmt.Fprintf(os.Stderr, "Starting key generation...\n\n")

	results, err := run(config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return
	}

	elapsed := time.Since(startTime).Seconds()
	cnt := atomic.LoadUint64(&keys)
	if elapsed > 0 {
		rate := float64(cnt) / elapsed
		_, _ = fmt.Fprintf(os.Stderr, "\nTotal: %d keys in %.1fs (%.0f keys/s)\n", cnt, elapsed, rate)
	}

	_, _ = fmt.Fprintf(os.Stderr, "\n✓ Found %d/%d keys!\n", len(results), len(config.Suffixes))
	for _, r := range results {
		_, _ = fmt.Fprintf(os.Stderr, "  - %s\n", r.Suffix)
	}
}
