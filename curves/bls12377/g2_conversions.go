//go:build g2

package bls12377

import (
	"fmt"

	bls12_377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377/g2"
)

func ToGnarkFp(f *g2.G2BaseField) *fp.Element {
	fb := f.ToBytesLittleEndian()
	var b48 [48]byte
	copy(b48[:], fb[:48])

	v, e := fp.LittleEndian.Element(&b48)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v; got error %v", f, e))
	}

	return &v
}

func ToGnarkE2(f *g2.G2BaseField) bls12_377.E2 {
	bytes := f.ToBytesLittleEndian()
	a0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(bytes[:len(bytes)/2]))
	a1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(bytes[len(bytes)/2:]))
	return bls12_377.E2{
		A0: a0,
		A1: a1,
	}
}

func GnarkE2Bits(f *bls12_377.E2) []uint64 {
	a0 := f.A0.Bits()
	a1 := f.A1.Bits()
	return append(a0[:], a1[:]...)
}

func FromGnarkE2(f *bls12_377.E2) g2.G2BaseField {
	var field g2.G2BaseField
	field.FromLimbs(core.ConvertUint64ArrToUint32Arr(GnarkE2Bits(f)))
	return field
}

func G2PointToGnarkJac(p *g2.G2Projective) *bls12_377.G2Jac {
	x := ToGnarkE2(&p.X)
	y := ToGnarkE2(&p.Y)
	z := ToGnarkE2(&p.Z)
	var zSquared bls12_377.E2
	zSquared.Mul(&z, &z)

	var X bls12_377.E2
	X.Mul(&x, &z)

	var Y bls12_377.E2
	Y.Mul(&y, &zSquared)

	after := bls12_377.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	return &after
}

func G2PointToGnarkAffine(p *g2.G2Projective) *bls12_377.G2Affine {
	var affine bls12_377.G2Affine
	affine.FromJacobian(G2PointToGnarkJac(p))
	return &affine
}

func G2AffineFromGnarkAffine(gnark *bls12_377.G2Affine, g *g2.G2Affine) *g2.G2Affine {
	g.X = FromGnarkE2(&gnark.X)
	g.Y = FromGnarkE2(&gnark.Y)
	return g
}

func G2PointAffineFromGnarkJac(gnark *bls12_377.G2Jac, g *g2.G2Affine) *g2.G2Affine {
	var pointAffine bls12_377.G2Affine
	pointAffine.FromJacobian(gnark)

	return G2AffineFromGnarkAffine(&pointAffine, g)
}

func BatchConvertFromG2Affine(elements []bls12_377.G2Affine) []g2.G2Affine {
	var newElements []g2.G2Affine
	for _, gg2Affine := range elements {
		var newElement g2.G2Affine
		G2AffineFromGnarkAffine(&gg2Affine, &newElement)

		newElements = append(newElements, newElement)
	}
	return newElements
}

func BatchConvertFromG2AffineThreaded(elements []bls12_377.G2Affine, routines int) []g2.G2Affine {
	var newElements []g2.G2Affine

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []g2.G2Affine, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []g2.G2Affine, 1)
		}

		convert := func(elements []bls12_377.G2Affine, chanIndex int) {
			var convertedElements []g2.G2Affine
			for _, e := range elements {
				var converted g2.G2Affine
				G2AffineFromGnarkAffine(&e, &converted)
				convertedElements = append(convertedElements, converted)
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
			var converted g2.G2Affine
			G2AffineFromGnarkAffine(&e, &converted)
			newElements = append(newElements, converted)
		}
	}

	return newElements
}
