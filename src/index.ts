import { Circomkit } from "circomkit";
import { AddressesIMT, PROOF_SYSTEM_CONSTANTS, SessionClaimsIMT } from "microch";
import { hexlify } from "ethers";
import { parseEther } from "viem";

async function main() {
  // create circomkit
  const circomkit = new Circomkit({
    protocol: "groth16",
  });

  // artifacts output at `build/account_transaction_validation_1_17_17` directory
  await circomkit.compile("account_transaction_validation_1_17_17", {
    file: "account_transaction_validation",
    template: "AccountTransactionValidation",
    params: [1, 17, 17],
    pubs: ["accountIdentifier", "op", "dest", "value", "functionSelector", "erc20TransferTo"]
  });

  //typescript type in the library
  const transaction1= {
    dest: BigInt("0x2555e3a97c4ac9705D70b9e5B9b6cc6Fe2977A74"),
    value: "0.01",
    functionSelector: BigInt("0x0"),
    Erc20TransferTo: BigInt("0x0")
  }

  //typescript type in the library
  const transactions = [
    transaction1
  ]

  const accountIdentifier= "0x8448Ff4b2733b52f62d81ca46d64bD16786299Cd";
  const toAddressesTree= new AddressesIMT(17, 0, 2);
  await toAddressesTree.addAddress(BigInt("0x2555e3a97c4ac9705D70b9e5B9b6cc6Fe2977A74"));
  await toAddressesTree.addAddress(BigInt("0xFAe129dafF0FB52fea5453479Dcb5AAfB8Fd4424"));
  await toAddressesTree.addAddress(BigInt("0x70c77a073de139c3B3FEA2C8F1DdF5cC90e969Cd"));


  const accountAllowedSmartContracts = ["0xEAd18b006203059D51933e6aDcDEdb8b5CE526E1"]

  const accountAllowedSmartContractTree: AddressesIMT = new AddressesIMT(17, 0, 2);

  for (let address of accountAllowedSmartContracts) {
      await accountAllowedSmartContractTree.addAddress(BigInt(address));
  }

  const accountTree = new SessionClaimsIMT(2, 0, 2);
  accountTree.addClaim(BigInt(accountIdentifier))
  accountTree.addClaim(BigInt(accountAllowedSmartContractTree.root));
  accountTree.addClaim(toAddressesTree.root)
  accountTree.addClaim(BigInt(0))

  let userOpHash= "0x9a58fb6799b1e11cc129a14592f0a75a00970cf141e2abfbf76d070d4c01f893"
  let op = BigInt(hexlify(userOpHash))
  op %= PROOF_SYSTEM_CONSTANTS.SNARK_SCALAR_FIELD

  //typescript type in the library
  const circuitInputs = {
    accountIdentifier: BigInt(accountIdentifier),
    allowedSmartContractTreeRoot: accountAllowedSmartContractTree.root,
    allowedToTreeRoot: toAddressesTree.root,
    op: op,
    dest:[] as bigint[],
    value: [] as bigint[],
    functionSelector: [] as bigint[], 
    erc20TransferTo:[] as bigint[], 
    EthToSiblings: [] as number[][], 
    EthToPathIndices: [] as number[][],     
    allowedSmartContractCallSiblings: [] as number[][],
    allowedSmartContractCallPathIndices: [] as number[][],
    Erc20ToAddressSiblings: [] as number[][],
    Erc20ToAddressPathIndices: [] as number[][] 
  }

  for(let tx of transactions){
    
    circuitInputs.dest.push(tx.dest)
    circuitInputs.value.push(parseEther(tx.value))
    circuitInputs.functionSelector.push(tx.functionSelector)
    circuitInputs.erc20TransferTo.push(tx.Erc20TransferTo)
    if(tx.value != "0"){
      const index= await toAddressesTree.indexOf(BigInt(tx.dest));
      const allowedToProof= await toAddressesTree.generateMerkleProof(index);
      circuitInputs.EthToSiblings.push(allowedToProof.siblings)
      circuitInputs.EthToPathIndices.push(allowedToProof.pathIndices)
    }else{
      //static value
      circuitInputs.EthToSiblings.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
      circuitInputs.EthToPathIndices.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    }

    if(tx.functionSelector != BigInt("0x0")){
      const index= await accountAllowedSmartContractTree.indexOf(BigInt(tx.dest));
      const allowedSmartContractProof= await accountAllowedSmartContractTree.generateMerkleProof(index);
      circuitInputs.allowedSmartContractCallSiblings.push(allowedSmartContractProof.siblings)
      circuitInputs.allowedSmartContractCallPathIndices.push(allowedSmartContractProof.pathIndices)
    }else{
      //static value
      circuitInputs.allowedSmartContractCallSiblings.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
      circuitInputs.allowedSmartContractCallPathIndices.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    }
    if(tx.Erc20TransferTo != BigInt("0x0")){
      const index= await toAddressesTree.indexOf(BigInt(tx.Erc20TransferTo));
      const allowedSmartContractProof= await toAddressesTree.generateMerkleProof(index);
      circuitInputs.Erc20ToAddressSiblings.push(allowedSmartContractProof.siblings)
      circuitInputs.Erc20ToAddressPathIndices.push(allowedSmartContractProof.pathIndices)
    }else{
      //static value
      circuitInputs.Erc20ToAddressSiblings.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
      circuitInputs.Erc20ToAddressPathIndices.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    }
  }


  //console.log(circuitInputs)
  // proof & public signals at `build/account_transaction_validation_1_17_17/my_input` directory
  await circomkit.prove("account_transaction_validation_1_17_17", "my_input", circuitInputs);

  // verify with proof & public signals at `build/account_transaction_validation_1_17_17/my_input`
  const ok = await circomkit.verify("account_transaction_validation_1_17_17", "my_input");
  if (ok) {
    circomkit.log("accountRoot: " + accountTree.root);
    circomkit.log("Proof verified!", "success");
  } else {
    circomkit.log("Verification failed.", "error");
  }
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });


