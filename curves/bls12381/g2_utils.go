//go:build g2

package bls12381

import (
	bls12_381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12381/g2"
)

func CopyG2PointsToDevice(points []bls12_381.G2Affine, pointsBytes int, copyDone chan core.DeviceSlice) {
	var devicePonts core.DeviceSlice
	if pointsBytes == 0 {
		copyDone <- devicePonts
	} else {
		iciclePoints := core.HostSliceFromElements(BatchConvertFromG2Affine(points))
		iciclePoints.CopyToDevice(&devicePonts, true)

		copyDone <- devicePonts
	}
}

func HostSliceFromG2Points(gnarkPoints []bls12_381.G2Affine) core.HostSlice[g2.G2Affine] {
	return core.HostSliceFromElements(BatchConvertFromG2Affine(gnarkPoints))
}
