package coco

import (
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)

const (
	// Hpcc Test Case.
	sampleSignedEncryptedContract = "../samples/hpcc/signed-encrypt-hpcc.yaml"
	sampleGzippedInidata          = "../samples/hpcc/gzipped-initdata"
)

// Testcase to check HpccGzippedInitdata() is able to gzip data.
func TestHpccGzippedInitdata(t *testing.T) {
	if !gen.CheckFileFolderExists(sampleSignedEncryptedContract) {
		t.Errorf("failed, file does not exits on defined path")
	}

	inputData, err := gen.ReadDataFromFile(sampleSignedEncryptedContract)
	if err != nil {
		t.Errorf("failed to read content form encrypted contract - %v", err)
	}

	encodedString, err := HpccGzippedInitdata(inputData)
	if err != nil {
		t.Errorf("failed to gzipped encoded initdata - %v", err)
	}

	expectedGzippedInitdata, err := gen.ReadDataFromFile(sampleGzippedInidata)
	if err != nil {
		t.Errorf("failed to read gzipped-initdata file - %v", err)
	}

	assert.Equal(t, expectedGzippedInitdata, encodedString, "Encoded gzipped initdata string does match with exepected gzipped initdata")
}

// Testcase to check HpccGzippedInitdata() is able to handle empty contract case.
func TestHpccGzippedInitdataEmptyContract(t *testing.T) {
	_, err := HpccGzippedInitdata("")
	assert.EqualError(t, err, emptyParameterErrStatement)	
}