### To execute the test

The coucheDB is already implemented inside the hyperledger so you need to remplace the file smartcontract on :
```Fabric/fabric-samples/asset-transfer-basic/chaincode-go/chaincode/smartcontract.go```

```go

/*
SPDX-License-Identifier: Apache-2.0
*/

package chaincode

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// SmartContract provides functions for managing Thesis records
type SmartContract struct {
	contractapi.Contract
}

// ThesisMetadata represents the nested metadata of a thesis record
type ThesisMetadata struct {
	ThesisTitle string `json:"thesisTitle"`
	DefenseDate string `json:"DefenseDate"`
}

// ThesisPayload represents the structural model stored in the ledger
type ThesisPayload struct {
	ThesisID string         `json:"thesisId"`
	Grade    float64        `json:"grade"`
	Metadata ThesisMetadata `json:"metadata"`
}

// InitLedger adds a base set of theses to the ledger for testing purposes
// func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
// 	theses := []ThesisPayload{
// 		{
// 			ThesisID: "thesis1",
// 			Grade:    14.5,
// 			Metadata: ThesisMetadata{ThesisTitle: "Digitalization of Agricultural Supply Chains", DefenseDate: "2026-06-15"},
// 		},
// 		{
// 			ThesisID: "thesis2",
// 			Grade:    16.0,
// 			Metadata: ThesisMetadata{ThesisTitle: "Blockchain Security and vHSM Architectures", DefenseDate: "2026-06-18"},
// 		},
// 		{
// 			ThesisID: "thesis3",
// 			Grade:    12.0,
// 			Metadata: ThesisMetadata{ThesisTitle: "Network Configurations in Linux Environments", DefenseDate: "2026-05-20"},
// 		},
// 	}

// 	for _, thesis := range theses {
// 		thesisJSON, err := json.Marshal(thesis)
// 		if err != nil {
// 			return err
// 		}

// 		err = ctx.GetStub().PutState(thesis.ThesisID, thesisJSON)
// 		if err != nil {
// 			return fmt.Errorf("failed to put to world state: %v", err)
// 		}
// 	}

// 	return nil
// }

// CreateThesis issues a new thesis record to the world state with given details.
func (s *SmartContract) CreateThesis(ctx contractapi.TransactionContextInterface, id string, grade float64, title string, defenseDate string) error {
	exists, err := s.ThesisExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the thesis %s already exists", id)
	}

	thesis := ThesisPayload{
		ThesisID: id,
		Grade:    grade,
		Metadata: ThesisMetadata{
			ThesisTitle: title,
			DefenseDate: defenseDate,
		},
	}
	
	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, thesisJSON)
}

// ReadThesis returns the thesis stored in the world state with given id.
func (s *SmartContract) ReadThesis(ctx contractapi.TransactionContextInterface, id string) (*ThesisPayload, error) {
	thesisJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if thesisJSON == nil {
		return nil, fmt.Errorf("the thesis %s does not exist", id)
	}

	var thesis ThesisPayload
	err = json.Unmarshal(thesisJSON, &thesis)
	if err != nil {
		return nil, err
	}

	return &thesis, nil
}

// UpdateThesis updates an existing thesis in the world state with provided parameters.
func (s *SmartContract) UpdateThesis(ctx contractapi.TransactionContextInterface, id string, grade float64, title string, defenseDate string) error {
	exists, err := s.ThesisExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the thesis %s does not exist", id)
	}

	thesis := ThesisPayload{
		ThesisID: id,
		Grade:    grade,
		Metadata: ThesisMetadata{
			ThesisTitle: title,
			DefenseDate: defenseDate,
		},
	}
	
	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, thesisJSON)
}

// DeleteThesis deletes a given thesis from the world state.
func (s *SmartContract) DeleteThesis(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.ThesisExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the thesis %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

// ThesisExists returns true when thesis with given ID exists in world state
func (s *SmartContract) ThesisExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	thesisJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return thesisJSON != nil, nil
}

// UpdateThesisGrade changes only the grade field of a thesis in the world state.
func (s *SmartContract) UpdateThesisGrade(ctx contractapi.TransactionContextInterface, id string, newGrade float64) error {
	thesis, err := s.ReadThesis(ctx, id)
	if err != nil {
		return err
	}

	thesis.Grade = newGrade

	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, thesisJSON)
}

// GetAllTheses returns all theses found in world state
func (s *SmartContract) GetAllTheses(ctx contractapi.TransactionContextInterface) ([]*ThesisPayload, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var theses []*ThesisPayload
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var thesis ThesisPayload
		err = json.Unmarshal(queryResponse.Value, &thesis)
		if err != nil {
			return nil, err
		}
		theses = append(theses, &thesis)
	}

	return theses, nil
}

```


1. Enter the hyperledger document Fabric/fabric-samples/test-network
2. shutdown properly the residual containers
```./network.sh down```
3. Relance the network on the default channel and coushBD
```./network.sh up createChannel -s couchdb```
4. deploy the smartContract
```./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go/ -ccl go -ccv 1.0 -ccs 1```
5. move to the document rest_api of he project 
```go run ../tests/rest_api/test_query.go```


<strong> If you wanna add a new Thesis for the test, run the docker and execute the command : </strong>
```go run ../tests/rest_api/test_gateway.go```