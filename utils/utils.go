package utils

import "github.com/tuneinsight/lattigo/v4/bfv"

const N = 10000
const Q_int_coeff = 1000.0 // Q_int = Q_new * Q_int_coeff

var (
	FAST_BUT_NOT_128_SECURITY = bfv.ParametersLiteral{
		LogN: 4,
		Q:    []uint64{0x7ffffec001, 0x8000016001}, // 39 + 39 bits
		P:    []uint64{0x40002001},                 // 30 bits
		T:    65537,
	}
)

// [-N, N] -> [0, 2N]
func MapInteger(x int64) uint64 {
	// Check if x is negative and map accordingly.
	if x < 0 {
		return uint64(x + 2*N)
	}
	return uint64(x)
}

// [0, 2N] -> [-N, N]
func UnmapInteger(x uint64) int {
	if x > N {
		return int(x - 2*N)
	}
	return int(x)
}
