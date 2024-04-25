//go:build g2

package bw6761

import (
	"fmt"

	bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	core "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bw6761/g2"
)

func ToGnarkFp(f *g2.G2BaseField) *fp.Element {
	fb := f.ToBytesLittleEndian()
	var b96 [96]byte
	copy(b96[:], fb[:96])

	v, e := fp.LittleEndian.Element(&b96)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v; got error %v", f, e))
	}

	return &v
}

func G2PointToGnarkJac(p *g2.G2Projective) *bw6_761.G2Jac {
	x := ToGnarkFp(&p.X)
	y := ToGnarkFp(&p.Y)
	z := ToGnarkFp(&p.Z)
	var zSquared fp.Element
	zSquared.Mul(z, z)

	var X fp.Element
	X.Mul(x, z)

	var Y fp.Element
	Y.Mul(y, &zSquared)

	after := bw6_761.G2Jac{
		X: X,
		Y: Y,
		Z: *z,
	}

	return &after
}

func G2PointToGnarkAffine(p *g2.G2Projective) *bw6_761.G2Affine {
	var affine bw6_761.G2Affine
	affine.FromJacobian(G2PointToGnarkJac(p))
	return &affine
}

func G2AffineFromGnarkAffine(gnark *bw6_761.G2Affine, g *g2.G2Affine) *g2.G2Affine {
	xBits := gnark.X.Bits()
	yBits := gnark.Y.Bits()
	g.X.FromLimbs(core.ConvertUint64ArrToUint32Arr(xBits[:]))
	g.Y.FromLimbs(core.ConvertUint64ArrToUint32Arr(yBits[:]))
	return g
}

func G2PointAffineFromGnarkJac(gnark *bw6_761.G2Jac, g *g2.G2Affine) *g2.G2Affine {
	var pointAffine bw6_761.G2Affine
	pointAffine.FromJacobian(gnark)

	return G2AffineFromGnarkAffine(&pointAffine, g)
}

func BatchConvertFromG2Affine(elements []bw6_761.G2Affine) []g2.G2Affine {
	var newElements []g2.G2Affine
	for _, gg2Affine := range elements {
		var newElement g2.G2Affine
		G2AffineFromGnarkAffine(&gg2Affine, &newElement)

		newElements = append(newElements, newElement)
	}
	return newElements
}

func BatchConvertFromG2AffineThreaded(elements []bw6_761.G2Affine, routines int) []g2.G2Affine {
	var newElements []g2.G2Affine

	if routines > 1 && routines <= len(elements) {
		channels := make([]chan []g2.G2Affine, routines)
		for i := 0; i < routines; i++ {
			channels[i] = make(chan []g2.G2Affine, 1)
		}

		convert := func(elements []bw6_761.G2Affine, chanIndex int) {
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
