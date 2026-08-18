package filter

import (
	"encoding/json"
	"fmt"
)

// Event represents a Server-Sent Event
type Event struct {
	Type string
	Data interface{}
}

// Subscribe creates a new SSE subscriber channel
func (f *FilterObserver) Subscribe() chan Event {
	ch := make(chan Event, 100)

	f.subscribersMu.Lock()
	f.subscribers[ch] = true
	f.subscribersMu.Unlock()

	return ch
}

// Unsubscribe removes a subscriber channel
func (f *FilterObserver) Unsubscribe(ch chan Event) {
	f.subscribersMu.Lock()
	delete(f.subscribers, ch)
	f.subscribersMu.Unlock()
	close(ch)
}

// publishEvent publishes an event to all subscribers (non-blocking)
func (f *FilterObserver) publishEvent(eventType string, data interface{}) {
	event := Event{
		Type: eventType,
		Data: data,
	}

	f.subscribersMu.RLock()
	defer f.subscribersMu.RUnlock()

	for ch := range f.subscribers {
		// Non-blocking send: drop event if subscriber is slow
		select {
		case ch <- event:
		default:
			// Subscriber is slow, drop the event
		}
	}
}

// FormatSSE formats an event as Server-Sent Events protocol
func FormatSSE(event Event) (string, error) {
	dataJSON, err := json.Marshal(event.Data)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("event: %s\ndata: %s\n\n", event.Type, string(dataJSON)), nil
}
