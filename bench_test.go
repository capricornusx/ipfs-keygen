package main

import (
	"sync/atomic"
	"testing"
	"time"

	crp "github.com/libp2p/go-libp2p/core/crypto"
	peer "github.com/libp2p/go-libp2p/core/peer"
	mbase "github.com/multiformats/go-multibase"
)

func Benchmark_SingleParallel(b *testing.B) {
	var keys uint64
	start := time.Now()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			priv, pub, err := crp.GenerateKeyPair(crp.Ed25519, 0)
			if err != nil {
				continue
			}
			pid, err := peer.IDFromPublicKey(pub)
			if err != nil {
				continue
			}
			_, _ = peer.ToCid(pid).StringOfBase(mbase.Base36)
			_ = priv
			atomic.AddUint64(&keys, 1)
		}
	})

	elapsed := time.Since(start)
	b.ReportMetric(float64(atomic.LoadUint64(&keys))/elapsed.Seconds(), "keys/s")
}
