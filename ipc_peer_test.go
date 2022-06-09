package bdls

import (
	"log"
	"testing"
	"time"
)

func TestLatencyDistribution200ms(t *testing.T) {
	p := NewIPCPeer(nil, 200*time.Millisecond)
	for i := 0; i < 100; i++ {
		log.Println(p.delay())
	}
}

func TestLatencyDistribution500ms(t *testing.T) {
	p := NewIPCPeer(nil, 500*time.Millisecond)
	for i := 0; i < 100; i++ {
		log.Println(p.delay())
	}
}
