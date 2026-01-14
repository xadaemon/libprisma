package cryptography

import (
	"errors"
	"testing"
)

func TestPad(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		blockSize  int
		wantLength int
		expectErr  bool
	}{
		{
			name:       "Empty Data",
			data:       []byte(""),
			blockSize:  16,
			wantLength: 16,
			expectErr:  true,
		},
		{
			name:       "BlockSize Less Than Data Length",
			data:       []byte("hello"),
			blockSize:  3,
			wantLength: 6,
			expectErr:  true,
		},
		{
			name:       "Block ends in 0",
			data:       []byte("hello\u0000"),
			blockSize:  6,
			wantLength: 12,
		},
		{
			name:       "BlockSize Equal To Data Length",
			data:       []byte("hello"),
			blockSize:  5,
			wantLength: 10,
		},
		{
			name:       "BlockSize Greater Than Data Length",
			data:       []byte("hello"),
			blockSize:  10,
			wantLength: 10,
		},
		{
			name:       "BlockSize Is Zero",
			data:       []byte("hello"),
			blockSize:  0,
			wantLength: 5,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Pad(tt.data, tt.blockSize)
			if err != nil && !tt.expectErr {
				t.Error("got error when it was not expected")
			} else if err != nil && tt.expectErr {
				return
			}
			if len(got) != tt.wantLength {
				t.Errorf("Pad() = %v, want %v", len(got), tt.wantLength)
			}
		})
	}
}

func TestUnpad(t *testing.T) {
	type testCase struct {
		desc    string
		data    []byte
		bs      int
		want    []byte
		wantErr error
		prePad  bool
	}

	testCases := []testCase{
		{
			desc:    "normal use",
			data:    []byte{1, 2, 3},
			bs:      16,
			want:    []byte{1, 2, 3},
			wantErr: nil,
		},
		{
			desc:    "empty data",
			data:    []byte{},
			bs:      4,
			want:    nil,
			wantErr: errors.New("empty data cannot be unpadded"),
		},
		{
			desc: "padding length is zero",
			data: []byte{1, 2, 3, 0},
			bs:   4,
			want: []byte{1, 2, 3, 0},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			var padded []byte
			paddedPost, _ := Pad(tC.data, tC.bs)
			if tC.prePad {
				padded = tC.data
			} else {
				padded = paddedPost
			}
			got, err := Unpad(padded, tC.bs)
			if err != nil {
				if tC.wantErr == nil {
					t.Errorf("Unexpected error: %v", err)
				} else if err.Error() != tC.wantErr.Error() {
					t.Errorf("Expected error %q, got %q", tC.wantErr.Error(), err.Error())
				}
			} else {
				if len(got) != len(tC.want) {
					t.Errorf("Expected len %d, got %d", len(tC.want), len(got))
				} else {
					for i := range got {
						if got[i] != tC.want[i] {
							t.Errorf("Expected data %v, got %v", tC.want, got)
						}
					}
				}
			}
		})
	}
}
