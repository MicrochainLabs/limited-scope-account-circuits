pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./tree.circom";
include "./operation_hasher.circom";

template AccountTransactionValidation(transactionNumber, smartContractTreeLevels, toTreeLevels) {

    signal input accountIdentifier;
    signal input allowedSmartContractTreeRoot;
    signal input allowedToTreeRoot;
    signal input op;

    //Extracted by the smart contract account (validateUserOp) from the user operation calldata 
    signal input dest[transactionNumber];
    signal input value[transactionNumber];
    signal input functionSelector[transactionNumber]; //(ERC20, transfer value) Hex: 0xa9059cbb
    signal input erc20TransferTo[transactionNumber];
    //signal input erc20amount[transactionNumber];
        
    signal input EthToSiblings[transactionNumber][toTreeLevels];
    signal input EthToPathIndices[transactionNumber][toTreeLevels];
    signal input allowedSmartContractCallSiblings[transactionNumber][smartContractTreeLevels];
    signal input allowedSmartContractCallPathIndices[transactionNumber][smartContractTreeLevels];
    signal input Erc20ToAddressSiblings[transactionNumber][toTreeLevels];
    signal input Erc20ToAddressPathIndices[transactionNumber][toTreeLevels];

    signal output accountRoot;
    signal output opHash;

    signal toTreeRootPerTransaction[transactionNumber];
    signal computedToTreeRootPerTransaction[transactionNumber];
    signal smartContractCallTreeRootPerTransaction[transactionNumber];
    signal computedSmartContractCallTreeRootPerTransaction[transactionNumber];
    signal erc20ToTreeRootPerTransaction[transactionNumber];
    signal computedErc20ToTreeRootPerTransaction[transactionNumber];


    //Compute account tree root
    component accountTree01 = Poseidon(2);
    accountTree01.inputs[0] <== accountIdentifier;
    accountTree01.inputs[1] <== allowedSmartContractTreeRoot;

    component accountTree23 = Poseidon(2);
    accountTree23.inputs[0] <== allowedToTreeRoot;
    accountTree23.inputs[1] <== 0;

    component accountTree = Poseidon(2);
    accountTree.inputs[0] <== accountTree01.out;
    accountTree.inputs[1] <== accountTree23.out;
    accountRoot <== accountTree.out;


    component isZeroEthAmount[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        isZeroEthAmount[i] = IsZero();
        isZeroEthAmount[i].in <== value[i];
    }
    component ethTransferToAddressInclusionValidity[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        ethTransferToAddressInclusionValidity[i] = MerkleTreeInclusionProof(toTreeLevels);
        ethTransferToAddressInclusionValidity[i].leaf <== dest[i];
        for (var j=0; j<toTreeLevels; j++) {
            ethTransferToAddressInclusionValidity[i].siblings[j] <== EthToSiblings[i][j];
            ethTransferToAddressInclusionValidity[i].pathIndices[j] <== EthToPathIndices[i][j];
        }
    }
    for (var i=0; i<transactionNumber; i++) {
        toTreeRootPerTransaction[i] <== allowedToTreeRoot * (1 - isZeroEthAmount[i].out);
        computedToTreeRootPerTransaction[i] <== ethTransferToAddressInclusionValidity[i].root * (1 - isZeroEthAmount[i].out);
        toTreeRootPerTransaction[i] === computedToTreeRootPerTransaction[i];
    }


    
    component isZeroFunctionSelector[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        isZeroFunctionSelector[i] = IsZero();
        isZeroFunctionSelector[i].in <== functionSelector[i];
    }
    component callSmartContractAddressInclusionValidity[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        callSmartContractAddressInclusionValidity[i] = MerkleTreeInclusionProof(smartContractTreeLevels);
        callSmartContractAddressInclusionValidity[i].leaf <== dest[i];
        for (var j=0; j<smartContractTreeLevels; j++) {
            callSmartContractAddressInclusionValidity[i].siblings[j] <== allowedSmartContractCallSiblings[i][j];
            callSmartContractAddressInclusionValidity[i].pathIndices[j] <== allowedSmartContractCallPathIndices[i][j];
        }
    }
    for (var i=0; i<transactionNumber; i++) {
        smartContractCallTreeRootPerTransaction[i] <== allowedSmartContractTreeRoot * (1 - isZeroFunctionSelector[i].out);
        computedSmartContractCallTreeRootPerTransaction[i] <== callSmartContractAddressInclusionValidity[i].root * (1 - isZeroFunctionSelector[i].out);
        smartContractCallTreeRootPerTransaction[i] === computedSmartContractCallTreeRootPerTransaction[i];
    }


    //2835717307 transfer(to, amount) function selector
    component isErc20Transfer[transactionNumber];
     for (var i=0; i<transactionNumber; i++) {
        isErc20Transfer[i] = IsEqual();
        isErc20Transfer[i].in[0] <== 2835717307;
        isErc20Transfer[i].in[1] <== functionSelector[i];
    }
    component erc20TransferToAddressInclusionValidity[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        erc20TransferToAddressInclusionValidity[i] = MerkleTreeInclusionProof(toTreeLevels);
        erc20TransferToAddressInclusionValidity[i].leaf <== erc20TransferTo[i];
        for (var j=0; j<toTreeLevels; j++) {
            erc20TransferToAddressInclusionValidity[i].siblings[j] <== Erc20ToAddressSiblings[i][j];
            erc20TransferToAddressInclusionValidity[i].pathIndices[j] <== Erc20ToAddressPathIndices[i][j];
        }
    }
    for (var i=0; i<transactionNumber; i++) {
        erc20ToTreeRootPerTransaction[i] <== allowedToTreeRoot * isErc20Transfer[i].out;
        computedErc20ToTreeRootPerTransaction[i] <== erc20TransferToAddressInclusionValidity[i].root * isErc20Transfer[i].out;
        erc20ToTreeRootPerTransaction[i] === computedErc20ToTreeRootPerTransaction[i];
    }


    component operationHasher = OperationHasher();
    operationHasher.accountIdentifier <== accountIdentifier;
    operationHasher.secret <== accountRoot;
    operationHasher.op <== op;

    opHash <== operationHasher.opHash;

}

//component main {public [accountIdentifier, op, dest, value, functionSelector, erc20TransferTo]} = AccountTransactionValidation(1, 17, 17);