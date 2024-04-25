package bls12381

import (
	"fmt"

	bls12_381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	icicle_bls12_381 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12381"
)

func CopyScalarsToDevice(scalars []fr.Element, copyDone chan core.DeviceSlice) {
	icicleScalars := core.HostSliceFromElements(BatchConvertFromFrGnark(scalars))

	var deviceScalars core.DeviceSlice
	icicleScalars.CopyToDevice(&deviceScalars, true)
	icicle_bls12_381.AffineFromMontgomery(&deviceScalars)

	copyDone <- deviceScalars
}

func CopyPointsToDevice(points []bls12_381.G1Affine, copyDone chan core.DeviceSlice) {
	var devicePonts core.DeviceSlice
	if len(points) == 0 {
		copyDone <- devicePonts
	} else {
		iciclePoints := core.HostSliceFromElements(BatchConvertFromG1Affine(points))
		iciclePoints.CopyToDevice(&devicePonts, true)

		copyDone <- devicePonts
	}
}

func HostSliceFromScalars(gnarkScalars []fr.Element) core.HostSlice[icicle_bls12_381.ScalarField] {
	return core.HostSliceFromElements(BatchConvertFromFrGnark(gnarkScalars))
}

func HostSliceFromPoints(gnarkPoints []bls12_381.G1Affine) core.HostSlice[icicle_bls12_381.Affine] {
	return core.HostSliceFromElements(BatchConvertFromG1Affine(gnarkPoints))
}

func FreeDeviceSlice(deviceSlice core.DeviceSlice) {
	deviceSlice.Free()
}

func ScalarToGnarkFr(f *icicle_bls12_381.ScalarField) *fr.Element {
	fb := f.ToBytesLittleEndian()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fr.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func ScalarToGnarkFp(f *icicle_bls12_381.ScalarField) *fp.Element {
	fb := f.ToBytesLittleEndian()
	var b48 [48]byte
	copy(b48[:], fb[:48])

	v, e := fp.LittleEndian.Element(&b48)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func BatchConvertFromFrGnark(elements []fr.Element) []icicle_bls12_381.ScalarField {
	var newElements []icicle_bls12_381.ScalarField
	for _, e := range elements {
		converted := NewFieldFromFrGnark(e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertFromFrGnarkThreaded(elements []fr.Element, routines int) []icicle_bls12_381.ScalarField {
	var newElements []icicle_bls12_381.ScalarField

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []icicle_bls12_381.ScalarField, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []icicle_bls12_381.ScalarField, 1)
		}

		convert := func(elements []fr.Element, chanIndex int) {
			var convertedElements []icicle_bls12_381.ScalarField
			for _, e := range elements {
				converted := NewFieldFromFrGnark(e)
				convertedElements = append(convertedElements, *converted)
			}

			channels[chanIndex] <- convertedElements
		}

		batchLen := len(elements) / routines
		for i := 0; i < routines; i++ {
			start := batchLen * i
			end := batchLen * (i + 1)
			elemsToConv := elements[start:end]
			if i == routines-1 {
				elemsToConv = elements[start:]
			}
			go convert(elemsToConv, i)
		}

		for i := 0; i < routines; i++ {
			newElements = append(newElements, <-channels[i]...)
		}
	} else {
		for _, e := range elements {
			converted := NewFieldFromFrGnark(e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func BatchConvertBaseFieldToFrGnark(elements []icicle_bls12_381.BaseField) []fr.Element {
	var newElements []fr.Element
	for _, e := range elements {
		converted := BaseFieldToGnarkFr(&e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertScalarFieldToFrGnark(elements []icicle_bls12_381.ScalarField) []fr.Element {
	var newElements []fr.Element
	for _, e := range elements {
		converted := ScalarToGnarkFr(&e)
		newElements = append(newElements, *converted)
	}

	return newElements
}

func BatchConvertBaseFieldToFrGnarkThreaded(elements []icicle_bls12_381.BaseField, routines int) []fr.Element {
	var newElements []fr.Element

	if routines > 1 {
		channels := make([]chan []fr.Element, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []fr.Element, 1)
		}

		convert := func(elements []icicle_bls12_381.BaseField, chanIndex int) {
			var convertedElements []fr.Element
			for _, e := range elements {
				converted := BaseFieldToGnarkFr(&e)
				convertedElements = append(convertedElements, *converted)
			}

			channels[chanIndex] <- convertedElements
		}

		batchLen := len(elements) / routines
		for i := 0; i < routines; i++ {
			elemsToConv := elements[batchLen*i : batchLen*(i+1)]
			go convert(elemsToConv, i)
		}

		for i := 0; i < routines; i++ {
			newElements = append(newElements, <-channels[i]...)
		}
	} else {
		for _, e := range elements {
			converted := BaseFieldToGnarkFr(&e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func BatchConvertScalarFieldToFrGnarkThreaded(elements []icicle_bls12_381.ScalarField, routines int) []fr.Element {
	var newElements []fr.Element

	if routines > 1 {
		channels := make([]chan []fr.Element, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []fr.Element, 1)
		}

		convert := func(elements []icicle_bls12_381.ScalarField, chanIndex int) {
			var convertedElements []fr.Element
			for _, e := range elements {
				converted := ScalarToGnarkFr(&e)
				convertedElements = append(convertedElements, *converted)
			}

			channels[chanIndex] <- convertedElements
		}

		batchLen := len(elements) / routines
		for i := 0; i < routines; i++ {
			elemsToConv := elements[batchLen*i : batchLen*(i+1)]
			go convert(elemsToConv, i)
		}

		for i := 0; i < routines; i++ {
			newElements = append(newElements, <-channels[i]...)
		}
	} else {
		for _, e := range elements {
			converted := ScalarToGnarkFr(&e)
			newElements = append(newElements, *converted)
		}
	}

	return newElements
}

func NewFieldFromFrGnark(element fr.Element) *icicle_bls12_381.ScalarField {
	element_bits := element.Bits()
	s := core.ConvertUint64ArrToUint32Arr(element_bits[:]) // get non-montgomry

	var field icicle_bls12_381.ScalarField
	field.FromLimbs(s)
	return &field
}

func NewFieldFromFpGnark(element fp.Element) *icicle_bls12_381.BaseField {
	element_bits := element.Bits()
	s := core.ConvertUint64ArrToUint32Arr(element_bits[:]) // get non-montgomry

	var field icicle_bls12_381.BaseField
	field.FromLimbs(s)
	return &field
}

func BaseFieldToGnarkFr(f *icicle_bls12_381.BaseField) *fr.Element {
	v, _ := fr.LittleEndian.Element((*[fr.Bytes]byte)(f.ToBytesLittleEndian()))
	return &v
}

func BaseFieldToGnarkFp(f *icicle_bls12_381.BaseField) *fp.Element {
	v, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(f.ToBytesLittleEndian()))
	return &v
}
