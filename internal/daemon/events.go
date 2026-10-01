package daemon

import "sync"

// Event is something clients may want to show: a kernel log line, a
// traffic sample, or a change of state.
type Event struct {
	Type string `json:"type"` // log | traffic | state
	Data any    `json:"data"`
}

// Bus fans events out to subscribers. Slow subscribers miss events rather
// than slowing the daemon down.
type Bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe returns a channel of events and a function that ends the
// subscription.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[chan Event]struct{}{}
	}
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}
