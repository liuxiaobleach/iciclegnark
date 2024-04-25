package bls12381

import (
	"errors"

	bls12_381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	icicle_bls12_381 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12381"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12381/msm"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12381/ntt"
)

func MsmOnDevice(gnarkPoints []bls12_381.G1Affine, gnarkScalars []fr.Element) (*bls12_381.G1Affine, error) {
	iciclePoints := HostSliceFromPoints(gnarkPoints)
	icicleScalars := HostSliceFromScalars(gnarkScalars)

	cfg := core.GetDefaultMSMConfig()
	var p icicle_bls12_381.Projective
	var out core.DeviceSlice
	_, e := out.Malloc(p.Size(), p.Size())
	if e != cr.CudaSuccess {
		return nil, errors.New("cannot allocate")
	}
	e = msm.Msm(icicleScalars, iciclePoints, &cfg, out)
	if e != cr.CudaSuccess {
		return nil, errors.New("msm failed")
	}
	outHost := make(core.HostSlice[icicle_bls12_381.Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()
	return ProjectiveToGnarkAffine(&outHost[0]), nil
}

func Ntt[T any](gnarkScalars fr.Vector, dir core.NTTDir, cfg *core.NTTConfig[T]) (fr.Vector, error) {
	icicleScalars := core.HostSliceFromElements(BatchConvertFromFrGnark(gnarkScalars))
	output := make(core.HostSlice[icicle_bls12_381.ScalarField], len(gnarkScalars))
	res := ntt.Ntt(icicleScalars, dir, cfg, output)
	if res.IcicleErrorCode != core.IcicleErrorCode(0) {
		return nil, errors.New("ntt failed")
	}
	// TODO Reverse order processing
	// if cfg.Ordering == core.KNN || cfg.Ordering == core.KRR {

	// }
	return BatchConvertScalarFieldToFrGnark(output), nil
}

func NttOnDevice(gnarkScalars fr.Vector) (fr.Vector, error) {
	cfg := ntt.GetDefaultNttConfig()
	return Ntt(gnarkScalars, core.KForward, &cfg)
}

func INttOnDevice(gnarkScalars fr.Vector) (fr.Vector, error) {
	cfg := ntt.GetDefaultNttConfig()
	return Ntt(gnarkScalars, core.KInverse, &cfg)
}

// func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) unsafe.Pointer {
// 	ReverseScalars(scalars_d, size)

// 	scalarsInterp := icicle_bls12_381.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)

// 	return scalarsInterp
// }

// func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) {
// 	res := icicle_bls12_381.Ntt(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)

// 	if res.IcicleErrorCode != core.IcicleErrorCode(0) {
// 		fmt.Print("Issue evaluating")
// 	}

// 	ReverseScalars(scalars_out, size)
// }

// func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count int, convert bool) (bls12_381.G1Jac, unsafe.Pointer, error) {
// 	var p icicle_bls12_381.Projective
// 	var out_d core.DeviceSlice
// 	_, e := out_d.Malloc(p.Size(), p.Size())
// 	if e != cr.CudaSuccess {
// 		return bls12_381.G1Jac{}, nil, errors.New("Allocation error")
// 	}

// 	icicle_bls12_381.Msm((s))

// 	icicle_bls12_381.Msm(out_d, scalars_d, points_d, count, 10)

// 	if convert {
// 		outHost := make([]icicle_bls12_381.Projective, 1)
// 		cr.CopyFromDevice(outHost, out_d, uint(pointBytes))

// 		return *G1ProjectivePointToGnarkJac(&outHost[0]), nil, nil
// 	}

// 	return bls12_381.G1Jac{}, out_d, nil
// }

// func GenerateTwiddleFactors(size int, inverse bool) (unsafe.Pointer, error) {
// 	om_selector := int(math.Log(float64(size)) / math.Log(2))
// 	return icicle_bls12_381.GenerateTwiddles(size, om_selector, inverse)
// }

// func ReverseScalars(ptr unsafe.Pointer, size int) error {
// 	if success, err := icicle_bls12_381.ReverseScalars(ptr, size); success != 0 {
// 		return err
// 	}

// 	return nil
// }

// func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) {
// 	ret := icicle_bls12_381.VecScalarMulMod(a_d, b_d, size)

// 	if ret != 0 {
// 		fmt.Print("Vector mult a*b issue")
// 	}
// 	ret = icicle_bls12_381.VecScalarSub(a_d, c_d, size)

// 	if ret != 0 {
// 		fmt.Print("Vector sub issue")
// 	}
// 	ret = icicle_bls12_381.VecScalarMulMod(a_d, den_d, size)

// 	if ret != 0 {
// 		fmt.Print("Vector mult a*den issue")
// 	}
// }

// func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) {
// 	if is_into {
// 		icicle_bls12_381.ToMontgomery(scalars_d, size)
// 	} else {
// 		icicle_bls12_381.FromMontgomery(scalars_d, size)
// 	}
// }
