package main

import (
	"fmt"
	"hash"

	"github.com/consensys/gnark-crypto/ecc"
	hashMimc "github.com/consensys/gnark-crypto/hash"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/gkr"
	stdHash "github.com/consensys/gnark/std/hash"
	hashMimcCircuit "github.com/consensys/gnark/std/hash/mimc"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type myCircuit struct {
	// default uses variable name and secret visibility.
	X       []frontend.Variable
	Y       []frontend.Variable
	Z       []frontend.Variable
	counter int
	api     frontend.API
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *myCircuit) Define(api frontend.API) error {
	_gkr := gkr.NewApi()

	x, err := _gkr.Import(circuit.X)

	if err != nil {
		return err
	}

	y, err := _gkr.Import(circuit.Y)
	if err != nil {
		return err
	}
	z := _gkr.Add(x, y)

	solution, err := _gkr.Solve(api)
	if err != nil {
		return err
	}

	Z_gkr := solution.Export(z)
	println(Z_gkr)
	err = solution.Verify("mimc", 134234)
	api.AssertIsEqual(circuit.Z[0], Z_gkr[0])

	return nil
}

func InitializeBalanceGKR() {
	bn254r1cs.RegisterHashBuilder("mimc", func() hash.Hash {
		return hashMimc.MIMC_BN254.New()
	})
	stdHash.Register("mimc", func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := hashMimcCircuit.NewMiMC(api)
		return &m, err
	})
}

func main() {
	// compiles our circuit into a R1CS
	circuit := myCircuit{
		X: []frontend.Variable{200000000000000000},
		Y: []frontend.Variable{20},
		Z: []frontend.Variable{2088888888888888},
	}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	fmt.Println(ccs.GetNbConstraints())
	fmt.Println(ccs.GetNbVariables())
	fmt.Println(ccs.GetNbInstructions())

}
