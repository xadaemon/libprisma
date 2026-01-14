package memkv

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

type Opts struct {
	CaseInsensitive bool
}

type EventType int

const (
	E_KEY_CREATED  = iota
	E_KEY_UPDATED  = iota
	E_KEY_ACCESSED = iota
)

type Event struct {
	Key        string
	Type       EventType
	When       time.Time
	Success    bool
	FailReason string
	OldVal     any
	NewVal     any
}

type WatchHook func(e Event)
type Trigger func(self *MemKV, e Event)

type eHandler struct {
	hook         WatchHook
	trigger      Trigger
	eventsFilter []EventType
}

type MemKV struct {
	l         sync.RWMutex
	sep       string
	caseSense bool
	m         map[string]any
	watchers  map[string][]eHandler
}

// NewMemKV returns a new instance of MemKV with the specified separator and options.
// If opts is nil, default options are used. If CaseInsensitive option is set to true,
// the keys are treated as case-insensitive.
// If a key contains sep, then it's treated as a path to a nested key
func NewMemKV(sep string, opts *Opts) *MemKV {
	s := &MemKV{
		l:         sync.RWMutex{},
		sep:       sep,
		caseSense: true,
		m:         make(map[string]any),
		watchers:  make(map[string][]eHandler),
	}

	if opts == nil {
		return s
	}

	if opts.CaseInsensitive {
		s.caseSense = false
	}

	return s
}

func (m *MemKV) GetSerializableMap() map[string]any {
	return map[string]any{
		"__data": m.m,
		"__meta": map[string]any{
			"__serializedProtocol": 1,
			"caseSensitive":        m.caseSense,
			"separator":            m.sep,
		},
	}
}

func (m *MemKV) LoadFromSerializableMap(data map[string]any) error {
	m.l.Lock()
	defer m.l.Unlock()
	meta, ok := data["__meta"].(map[string]any)
	if !ok {
		return errors.New("meta data not found")
	}
	m.sep = meta["separator"].(string)
	m.caseSense = meta["caseSensitive"].(bool)
	m.m = data["__data"].(map[string]any)
	return nil
}

func (m *MemKV) Get(key string) (any, bool) {
	m.l.RLock()
	defer m.l.RUnlock()
	if !m.caseSense {
		key = strings.ToLower(key)
	}
	view := m.m
	keys := strings.Split(key, ".")
	if strings.Contains(key, ".") {
		for i, k := range keys {
			if i == len(keys)-1 {
				break
			}
			viewTemp, ok := view[k].(map[string]any)
			if !ok {
				return nil, false
			}
			view = viewTemp
		}
	}
	key = keys[len(keys)-1]
	val, ok := view[key]
	if !ok {
		return nil, ok
	}
	e := Event{
		Key:     key,
		Type:    E_KEY_ACCESSED,
		When:    time.Now(),
		Success: true,
	}
	m.dispatchWatchers(e)
	return val, true
}

func (m *MemKV) Set(key string, val any) bool {
	m.l.Lock()
	defer m.l.Unlock()
	if !m.caseSense {
		key = strings.ToLower(key)
	}
	view := m.m
	keys := strings.Split(key, ".")
	if strings.Contains(key, ".") {
		for i, k := range keys {
			if i == len(keys)-1 {
				break
			}
			if v, ok := view[k]; !ok {
				view[k] = map[string]any{}
				view = view[k].(map[string]any)
			} else {
				viewTemp, ok := v.(map[string]any)
				if !ok {
					return false
				}
				view = viewTemp
			}
		}
	}
	key = keys[len(keys)-1]
	if v, ok := view[key]; !ok {
		e := Event{
			Key:     key,
			Type:    E_KEY_CREATED,
			NewVal:  val,
			When:    time.Now(),
			Success: true,
		}
		m.dispatchWatchers(e)
	} else {
		e := Event{
			Key:     key,
			Type:    E_KEY_UPDATED,
			NewVal:  val,
			OldVal:  v,
			When:    time.Now(),
			Success: true,
		}
		m.dispatchWatchers(e)
	}
	view[key] = val
	return true
}

func (m *MemKV) Contains(key string) bool {
	_, ok := m.Get(key)
	return ok
}

// Drop deletes a key-value pair from the MemKV instance.
// It returns true if the key exists and was successfully deleted,
// and false otherwise. If deleteKeySpaces is true and the value of
// the key is a KeySpace type, the entire key space is deleted.
func (m *MemKV) Drop(key string, deleteKeySpaces bool) bool {
	if !strings.Contains(key, m.sep) {
		delete(m.m, key)
		return true
	}
	if !m.Contains(key) {
		return false
	}
	if m.IsKeySpace(key) {
		if !deleteKeySpaces {
			return false
		}
	}
	keys := strings.Split(key, m.sep)
	path := strings.Join(keys[:len(keys)-1], m.sep)
	key = keys[len(keys)-1]
	parent, _ := m.Get(path)
	m.l.Lock()
	defer m.l.Unlock()
	delete(parent.(map[string]any), key)
	return true
}

func (m *MemKV) IsKeySpace(key string) bool {
	v, ok := m.Get(key)
	if !ok {
		return false
	}
	if _, ok := v.(map[string]any); ok {
		return true
	}

	return false
}

func (m *MemKV) dispatchWatchers(e Event) {
	var wg sync.WaitGroup
	for _, w := range m.watchers[e.Key] {
		if slices.Contains(w.eventsFilter, e.Type) && w.hook != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.hook(e)
			}()
		}
	}
	wg.Wait()
}

func (m *MemKV) AddWatcherHook(key string, hook WatchHook, eFilter []EventType) {
	m.l.Lock()
	defer m.l.Unlock()
	if !m.caseSense {
		key = strings.ToLower(key)
	}

	handler := eHandler{
		hook:         hook,
		trigger:      nil,
		eventsFilter: eFilter,
	}

	if _, ok := m.watchers[key]; !ok {
		m.watchers[key] = []eHandler{handler}
	} else {
		m.watchers[key] = append(m.watchers[key], handler)
	}
}

func (m *MemKV) ImportMap(data map[string]any) {
	m.l.Lock()
	defer m.l.Unlock()
	for k, v := range data {
		m.m[k] = v
	}
}
