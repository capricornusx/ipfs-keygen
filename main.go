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
	keys      atomic.Uint64
	startTime time.Time
)

type SearchMode int

const (
	ModeAll    SearchMode = iota // ищем и в PeerID, и в IPNS
	ModePeerID                   // только PeerID
	ModeIPNS                     // только IPNS (base36)
)

const (
	modePeerID    = "peerid"
	modeIPNS      = "ipns"
	permKeyDir    = 0o755
	permKeyFile   = 0o600
	asciiCaseDiff = 'a' - 'A'
	minSuffixLen  = 4
)

func (m SearchMode) String() string {
	switch m {
	case ModeAll:
		return "all"
	case ModePeerID:
		return modePeerID
	case ModeIPNS:
		return modeIPNS
	default:
		return "unknown"
	}
}

func parseMode(s string) (SearchMode, error) {
	switch strings.ToLower(s) {
	case "all":
		return ModeAll, nil
	case modePeerID, "peer":
		return ModePeerID, nil
	case modeIPNS:
		return ModeIPNS, nil
	default:
		return ModeAll, fmt.Errorf("unknown mode: %s (valid: all, %s, %s)", s, modePeerID, modeIPNS)
	}
}

func main() {
	key := flag.String("key", "", "specify the location of the key to read")
	timeout := flag.Duration("timeout", 10*time.Minute, "timeout for vanity key generation")
	suff := flag.String("suff", "", "comma-separated list of suffixes (min 4 chars each)")
	modeStr := flag.String("mode", "all", "search mode: all, peerid, ipns")

	flag.Parse()

	if *key != "" {
		if err := readKey(key); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *suff != "" {
		mode, err := parseMode(*modeStr)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		FastGeneration(*timeout, *suff, mode)
		return
	}

	_, _ = fmt.Fprintln(os.Stderr, "Usage:")
	_, _ = fmt.Fprintln(os.Stderr, "  Generate vanity key: ipfs-key -suff=test,cool -timeout=1m -mode=all")
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

	idAsb36, err := peer.ToCid(id).StringOfBase(mbase.Base36)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(
		os.Stderr,
		"Success!\nID for %s key: %s\nID (base36/IPNS): %s\nPrivate key (base64): %s\n",
		prvk.Type().String(),
		id.String(),
		idAsb36,
		base64.StdEncoding.EncodeToString(data),
	)

	return err
}

func saveToFile(data []byte, suffix, kind string) error {
	// Создаём директорию keys/<kind> если её нет
	dir := "keys/" + kind
	if err := os.MkdirAll(dir, permKeyDir); err != nil {
		return err
	}

	// Формируем имя файла: keys/<kind>/suffix_timestamp.key
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("%s/%s_%s.key", dir, suffix, timestamp)

	// Сохраняем ключ
	if err := os.WriteFile(fileName, data, permKeyFile); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "💾 Key saved: %s\n\n", fileName)
	return nil
}

type Config struct {
	NumWorkers     int
	Suffixes       []string
	SuffixesBytes  [][]byte // Предкомпилированные суффиксы в base36
	Timeout        time.Duration
	ActiveSuffixes *sync.Map // Потокобезопасная карта активных суффиксов
	Mode           SearchMode
}

type Result struct {
	Found    bool
	String   string
	Suffix   string
	WorkerID int
	Kind     string
}

func NewConfig(suffixes []string, timeout time.Duration, mode SearchMode) Config {
	suffixesBytes := make([][]byte, len(suffixes))
	activeSuffixes := &sync.Map{}
	for i, s := range suffixes {
		suffixesBytes[i] = []byte(s)
		activeSuffixes.Store(s, true)
	}
	return Config{
		NumWorkers:     runtime.NumCPU(),
		Suffixes:       suffixes,
		SuffixesBytes:  suffixesBytes,
		Timeout:        timeout,
		ActiveSuffixes: activeSuffixes,
		Mode:           mode,
	}
}

func hasSuffixBytes(s string, suffix []byte) bool {
	if len(s) < len(suffix) {
		return false
	}
	offset := len(s) - len(suffix)
	for j := 0; j < len(suffix); j++ {
		if s[offset+j] != suffix[j] {
			return false
		}
	}
	return true
}

func hasSuffixCaseInsensitive(s string, suffix []byte) bool {
	if len(s) < len(suffix) {
		return false
	}
	offset := len(s) - len(suffix)
	for j := 0; j < len(suffix); j++ {
		if toLower(s[offset+j]) != toLower(suffix[j]) {
			return false
		}
	}
	return true
}

func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + asciiCaseDiff
	}
	return b
}

func matchKind(config Config, pidStr, privateKeyAsb36 string, needle []byte) string {
	switch config.Mode {
	case ModePeerID:
		if hasSuffixCaseInsensitive(pidStr, needle) {
			return modePeerID
		}
	case ModeIPNS:
		if hasSuffixBytes(privateKeyAsb36, needle) {
			return modeIPNS
		}
	case ModeAll:
		if hasSuffixCaseInsensitive(pidStr, needle) {
			return modePeerID
		} else if hasSuffixBytes(privateKeyAsb36, needle) {
			return modeIPNS
		}
	}
	return ""
}

func processGeneratedKey(config Config, priv crp.PrivKey, pidStr, privateKeyAsb36 string, id int, resultChan chan Result) bool {
	for _, needle := range config.SuffixesBytes {
		suffix := string(needle)
		// Проверяем, активен ли ещё этот суффикс
		if _, active := config.ActiveSuffixes.Load(suffix); !active {
			continue
		}

		kind := matchKind(config, pidStr, privateKeyAsb36, needle)
		if kind == "" {
			continue
		}

		// Пытаемся удалить суффикс (атомарно)
		if _, loaded := config.ActiveSuffixes.LoadAndDelete(suffix); !loaded {
			// Другой воркер уже нашёл этот суффикс
			continue
		}

		_, _ = fmt.Fprintf(
			os.Stdout,
			"ID for generated key: %s\nPKey(base36): %s\nMatched: %s\n",
			pidStr,
			privateKeyAsb36,
			kind,
		)

		data, _ := crp.MarshalPrivateKey(priv)
		if err := saveToFile(data, suffix, kind); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error saving key: %v\n", err)
		}

		resultChan <- Result{
			Found:    true,
			String:   privateKeyAsb36,
			Suffix:   suffix,
			WorkerID: id,
			Kind:     kind,
		}
		return true
	}
	return false
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
			keys.Add(localCounter)
			return
		default:
		}

		// Генерируем пачку ключей без проверки ctx
		for range 100 {
			priv, pub, err := crp.GenerateKeyPair(crp.Ed25519, 0)
			if err != nil {
				continue
			}

			pid, err := peer.IDFromPublicKey(pub)
			if err != nil {
				continue
			}

			pidStr := pid.String()
			privateKeyAsb36, _ := peer.ToCid(pid).StringOfBase(mbase.Base36)

			if processGeneratedKey(config, priv, pidStr, privateKeyAsb36, id, resultChan) {
				keys.Add(localCounter)
				localCounter = 0
			}

			localCounter++
		}

		if localCounter >= batchSize {
			keys.Add(batchSize)
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
				cnt := keys.Load()
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

func FastGeneration(timeout time.Duration, suff string, mode SearchMode) {
	suffixes := strings.Split(strings.TrimSpace(suff), ",")

	// Валидация суффиксов
	for _, s := range suffixes {
		if len(s) < minSuffixLen {
			_, _ = fmt.Fprintf(os.Stderr, "Error: suffix '%s' is too short (minimum 4 chars)\n", s)
			os.Exit(1)
		}
	}

	config := NewConfig(suffixes, timeout, mode)

	_, _ = fmt.Fprintf(os.Stderr, "Config: Workers=%d, Suffixes=%v, Timeout=%v, Mode=%s\n",
		config.NumWorkers, config.Suffixes, config.Timeout, config.Mode.String())
	_, _ = fmt.Fprintf(os.Stderr, "Starting key generation...\n\n")

	results, err := run(config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return
	}

	elapsed := time.Since(startTime).Seconds()
	cnt := keys.Load()
	if elapsed > 0 {
		rate := float64(cnt) / elapsed
		_, _ = fmt.Fprintf(os.Stderr, "\nTotal: %d keys in %.1fs (%.0f keys/s)\n", cnt, elapsed, rate)
	}

	_, _ = fmt.Fprintf(os.Stderr, "\n✓ Found %d/%d keys!\n", len(results), len(config.Suffixes))
	for _, r := range results {
		_, _ = fmt.Fprintf(os.Stderr, "  - %s (%s)\n", r.Suffix, r.Kind)
	}
}
