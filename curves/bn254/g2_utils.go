//go:build g2

package bn254

import (
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	core "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
)

func CopyG2PointsToDevice(points []bn254.G2Affine, pointsBytes int, copyDone chan core.DeviceSlice) {
	var devicePonts core.DeviceSlice
	if pointsBytes == 0 {
		copyDone <- devicePonts
	} else {
		iciclePoints := core.HostSliceFromElements(BatchConvertFromG2Affine(points))
		iciclePoints.CopyToDevice(&devicePonts, true)

		copyDone <- devicePonts
	}
}

func HostSliceFromG2Points(gnarkPoints []bn254.G2Affine) core.HostSlice[g2.G2Affine] {
	return core.HostSliceFromElements(BatchConvertFromG2Affine(gnarkPoints))
}
