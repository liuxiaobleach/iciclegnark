//go:build g2

package bn254

import (
	"errors"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
)

func G2MsmOnDevice(gnarkPoints []bn254.G2Affine, gnarkScalars []fr.Element) (*bn254.G2Affine, error) {
	iciclePoints := core.HostSliceFromElements(BatchConvertFromG2Affine(gnarkPoints))
	icicleScalars := core.HostSliceFromElements(BatchConvertFromFrGnark(gnarkScalars))

	cfg := core.GetDefaultMSMConfig()
	var p g2.G2Projective
	var out core.DeviceSlice
	_, e := out.Malloc(p.Size(), p.Size())
	if e != cr.CudaSuccess {
		return nil, errors.New("Cannot allocate")
	}
	e = g2.G2Msm(icicleScalars, iciclePoints, &cfg, out)
	if e != cr.CudaSuccess {
		return nil, errors.New("Msm failed")
	}
	outHost := make(core.HostSlice[g2.G2Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()
	return G2PointToGnarkAffine(&outHost[0]), nil
}
