package libprisma_test

import (
	"github.com/xadaemon/libprisma"
	"testing"
)

func TestMap(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		out  []libprisma.Result[int]
	}{
		{
			name: "success",
			in:   []int{1, 2, 3},
			out:  []libprisma.Result[int]{libprisma.Ok(2), libprisma.Ok(4), libprisma.Ok(6)},
		},
		{
			name: "empty",
			in:   []int{},
			out:  []libprisma.Result[int]{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := libprisma.Map(tt.in, func(i int) libprisma.Result[int] {
				return libprisma.Ok(i * 2)
			})

			if len(got) != len(tt.out) {
				t.Errorf("got %v, want %v", got, tt.out)
			}

			for i := range got {
				if got[i].ValueOrPanic() != tt.out[i].ValueOrPanic() {
					t.Errorf("got %v, want %v", got, tt.out)
				}
			}
		})
	}
}

func TestSwitch(t *testing.T) {
	nums := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		nums[i] = i
	}

	even, odd := libprisma.Switch(nums, func(i int) bool {
		return i%2 == 0
	})

	for _, n := range even {
		if n%2 != 0 {
			t.Errorf("got %v, want even", n)
		}
	}

	for _, n := range odd {
		if n%2 == 0 {
			t.Errorf("got %v, want odd", n)
		}
	}
}

func TestStreamingSwitch(t *testing.T) {
	nums := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		nums[i] = i
	}

	stream := make(chan int)
	even := make(chan int)
	odd := make(chan int)

	go libprisma.Stream(stream, nums)
	go libprisma.StreamingSwitch(stream, even, odd, func(i int) bool {
		return i%2 == 0
	})

	for {
		select {
		case n := <-even:
			if n%2 != 0 {
				t.Errorf("got %v, want even", n)
				t.Fail()
			}
		case n := <-odd:
			if n%2 == 0 {
				t.Errorf("got %v, want odd", n)
				t.Fail()
			}
		case _, ok := <-stream:
			if !ok {
				return
			}
		}
	}
}
