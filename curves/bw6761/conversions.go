package bw6761

import (
	bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	icicle_bw6_761 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bw6761"
)

func StripZ(p *icicle_bw6_761.Projective) *icicle_bw6_761.Affine {
	return &icicle_bw6_761.Affine{
		X: p.X,
		Y: p.Y,
	}
}

func BatchConvertFromG1Affine(elements []bw6_761.G1Affine) []icicle_bw6_761.Affine {
	var newElements []icicle_bw6_761.Affine
	for _, e := range elements {
		var newElement icicle_bw6_761.Projective
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *StripZ(&newElement))
	}
	return newElements
}

func ProjectiveToGnarkAffine(p *icicle_bw6_761.Projective) *bw6_761.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bw6_761.G1Affine{X: *x, Y: *y}
}

func G1ProjectivePointToGnarkJac(p *icicle_bw6_761.Projective) *bw6_761.G1Jac {
	var p1 bw6_761.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func FromG1AffineGnark(gnark *bw6_761.G1Affine, p *icicle_bw6_761.Projective) *icicle_bw6_761.Projective {
	var z icicle_bw6_761.BaseField
	z.One()

	p.X = *NewFieldFromFpGnark(gnark.X)
	p.Y = *NewFieldFromFpGnark(gnark.Y)
	p.Z = z

	return p
}

func G1ProjectivePointFromJacGnark(p *icicle_bw6_761.Projective, gnark *bw6_761.G1Jac) *icicle_bw6_761.Projective {
	var pointAffine bw6_761.G1Affine
	pointAffine.FromJacobian(gnark)

	var z icicle_bw6_761.BaseField
	z.One()

	p.X = *NewFieldFromFpGnark(pointAffine.X)
	p.Y = *NewFieldFromFpGnark(pointAffine.Y)
	p.Z = z

	return p
}

func AffineToGnarkAffine(p *icicle_bw6_761.Affine) *bw6_761.G1Affine {
	pointProjective := p.ToProjective()
	return ProjectiveToGnarkAffine(&pointProjective)
}
