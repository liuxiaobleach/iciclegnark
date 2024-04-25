//go:build g2

package bls12381

import (
	"errors"

	bls12_381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12381/g2"
)

func G2MsmOnDevice(gnarkPoints []bls12_381.G2Affine, gnarkScalars []fr.Element) (*bls12_381.G2Affine, error) {
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
