package bls12377

import (
	bls12_377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	icicle_bls12_377 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377"
)

func StripZ(p *icicle_bls12_377.Projective) *icicle_bls12_377.Affine {
	return &icicle_bls12_377.Affine{
		X: p.X,
		Y: p.Y,
	}
}

func BatchConvertFromG1Affine(elements []bls12_377.G1Affine) []icicle_bls12_377.Affine {
	var newElements []icicle_bls12_377.Affine
	for _, e := range elements {
		var newElement icicle_bls12_377.Projective
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *StripZ(&newElement))
	}
	return newElements
}

func ProjectiveToGnarkAffine(p *icicle_bls12_377.Projective) *bls12_377.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bls12_377.G1Affine{X: *x, Y: *y}
}

func G1ProjectivePointToGnarkJac(p *icicle_bls12_377.Projective) *bls12_377.G1Jac {
	var p1 bls12_377.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func FromG1AffineGnark(gnark *bls12_377.G1Affine, p *icicle_bls12_377.Projective) *icicle_bls12_377.Projective {
	var z icicle_bls12_377.BaseField
	z.One()

	p.X = *NewFieldFromFpGnark(gnark.X)
	p.Y = *NewFieldFromFpGnark(gnark.Y)
	p.Z = z

	return p
}

func G1ProjectivePointFromJacGnark(p *icicle_bls12_377.Projective, gnark *bls12_377.G1Jac) *icicle_bls12_377.Projective {
	var pointAffine bls12_377.G1Affine
	pointAffine.FromJacobian(gnark)

	var z icicle_bls12_377.BaseField
	z.One()

	p.X = *NewFieldFromFpGnark(pointAffine.X)
	p.Y = *NewFieldFromFpGnark(pointAffine.Y)
	p.Z = z

	return p
}

func AffineToGnarkAffine(p *icicle_bls12_377.Affine) *bls12_377.G1Affine {
	pointProjective := p.ToProjective()
	return ProjectiveToGnarkAffine(&pointProjective)
}
