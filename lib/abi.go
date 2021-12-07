package lib

import (
	"encoding/hex"
	"io"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/pkg/errors"
)

// DecodeABI decodes the given transaction input using the abi provided.
func DecodeABI(txInput string, abiReader io.Reader) (map[string]interface{}, error) {
	bi, err := abi.JSON(abiReader)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse ABI")
	}

	decodedSig, err := hex.DecodeString(txInput[2:10])
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode tx input method signature")
	}

	method, err := bi.MethodById(decodedSig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get method call")
	}

	decodedData, err := hex.DecodeString(txInput[10:])
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode tx input payload")
	}

	m := map[string]interface{}{}
	err = method.Inputs.UnpackIntoMap(m, decodedData)
	if err != nil {
		return nil, errors.Wrap(err, "unable to unpack decoded data into map")
	}

	return m, nil
}

// EncodeABI encodes the given method and arguments using the abi provided.
func EncodeABI(method string, args []interface{}, abiReader io.Reader) (string, error) {
	bi, err := abi.JSON(abiReader)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse ABI")
	}

	encoded, err := bi.Pack(method, args...)
	if err != nil {
		return "", errors.Wrap(err, "unable to encode method to conform to abi")
	}

	return hex.EncodeToString(encoded), nil
}
