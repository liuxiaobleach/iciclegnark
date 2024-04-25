//go:build g2

package bw6761

import (
	bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	core "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bw6761/g2"
)

func CopyG2PointsToDevice(points []bw6_761.G2Affine, pointsBytes int, copyDone chan core.DeviceSlice) {
	var devicePonts core.DeviceSlice
	if pointsBytes == 0 {
		copyDone <- devicePonts
	} else {
		iciclePoints := core.HostSliceFromElements(BatchConvertFromG2Affine(points))
		iciclePoints.CopyToDevice(&devicePonts, true)

		copyDone <- devicePonts
	}
}

func HostSliceFromG2Points(gnarkPoints []bw6_761.G2Affine) core.HostSlice[g2.G2Affine] {
	return core.HostSliceFromElements(BatchConvertFromG2Affine(gnarkPoints))
}
