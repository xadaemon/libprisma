package memkv_test

import (
	"github.com/xadaemon/libprisma/memkv"
	"testing"
)

type expectedValues struct {
	k    string
	v    int
	fail bool
}

func TestMemKV_Get(t *testing.T) {
	tests := []struct {
		Name   string
		Expect []expectedValues
	}{
		{
			Name: "Find simple",
			Expect: []expectedValues{
				{k: "testKey", v: 123},
			},
		},
		{
			Name: "Find path",
			Expect: []expectedValues{
				{k: "Some.test.path", v: 42},
			},
		},
		{
			Name: "Get multi path",
			Expect: []expectedValues{
				{k: "Some.test.path", v: 42},
				{k: "Some.test.leaf", v: 100},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			kvs := memkv.NewMemKV(".", nil)
			for _, e := range tt.Expect {
				kvs.Set(e.k, e.v)
				if v, ok := kvs.Get(e.k); ok {
					if v != e.v {
						t.Error("Failed to retrieve expected value")
					}
				}
			}
		})
	}
}

func TestMemKV_Set(t *testing.T) {
	tests := []struct {
		Name   string
		Expect []expectedValues
	}{
		{
			Name: "Set simple",
			Expect: []expectedValues{
				{k: "testKey", v: 123},
			},
		},
		{
			Name: "Set path",
			Expect: []expectedValues{
				{k: "Some.test.path", v: 42},
			},
		},
		{
			Name: "Set multi path",
			Expect: []expectedValues{
				{k: "Some.test.path", v: 42},
				{k: "Some.test.leaf", v: 100},
				{k: "Some.test.leaf.notAllowed", v: 100, fail: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			kvs := memkv.NewMemKV(".", nil)
			for _, e := range tt.Expect {
				if ok := kvs.Set(e.k, e.v); !ok && !e.fail {
					t.Error("Failed to set key unexpectedly")
				} else if ok && e.fail {
					t.Errorf("Succeess when failure was expected")
				}
				v, _ := kvs.Get(e.k)
				if v != e.v && !e.fail {
					t.Error("Failed to retrieve expected value")
				}
			}
		})
	}
}

func TestMemKV_Contains(t *testing.T) {
	kvs := memkv.NewMemKV(".", &memkv.Opts{CaseInsensitive: true})
	kvs.Set("TestKey", 42)
	if !kvs.Contains("TestKey") || !kvs.Contains("testkey") {
		t.Error("contains failed")
	}
}

func TestMemKV_AddWatcherHook(t *testing.T) {
	kvs := memkv.NewMemKV(".", nil)
	var gotWrite, gotRead int

	readHookFn := func(e memkv.Event) {
		gotRead += 1
	}
	writeHookFn := func(e memkv.Event) {
		gotWrite += 1
	}

	kvs.AddWatcherHook("TestKey", readHookFn, []memkv.EventType{memkv.E_KEY_ACCESSED})
	kvs.AddWatcherHook("TestKey", writeHookFn, []memkv.EventType{memkv.E_KEY_CREATED, memkv.E_KEY_UPDATED})

	kvs.Set("TestKey", 42)
	kvs.Set("TestKey", 100)
	kvs.Get("TestKey")

	if gotWrite != 2 || gotRead != 1 {
		t.Error("Unexpected access numbers")
	}
}

func TestMemKV_Drop(t *testing.T) {
	tests := []struct {
		Name            string
		SetupKeys       []expectedValues
		DropKey         string
		LookUp          string
		DeleteKeySpaces bool
		ExpectedSuccess bool
	}{
		{
			Name: "Drop simple key",
			SetupKeys: []expectedValues{
				{k: "testKey", v: 123},
			},
			DropKey:         "testKey",
			DeleteKeySpaces: false,
			ExpectedSuccess: true,
		},
		{
			Name: "Drop leaf key",
			SetupKeys: []expectedValues{
				{k: "Some.test.path", v: 42},
			},
			DropKey:         "Some.test.path",
			DeleteKeySpaces: false,
			ExpectedSuccess: true,
		},
		{
			Name: "Ignore drop key space",
			SetupKeys: []expectedValues{
				{k: "Some.test.path", v: 42},
			},
			DropKey:         "Some.test",
			DeleteKeySpaces: false,
			ExpectedSuccess: false,
		},
		{
			Name: "Drop key space",
			SetupKeys: []expectedValues{
				{k: "Some.test.path.withLeaf", v: 42},
			},
			DropKey:         "Some.test",
			LookUp:          "Some.test.path",
			DeleteKeySpaces: true,
			ExpectedSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			kvs := memkv.NewMemKV(".", nil)
			for _, e := range tt.SetupKeys {
				kvs.Set(e.k, e.v)
			}
			success := kvs.Drop(tt.DropKey, tt.DeleteKeySpaces)
			if success != tt.ExpectedSuccess {
				t.Errorf("Unexpected drop result, got %v, want %v", success, tt.ExpectedSuccess)
			}
			if tt.ExpectedSuccess && kvs.Contains(tt.DropKey) {
				t.Error("KeyFromStr is not dropped")
			}
		})
	}
}
