const Web3 = require('web3');
const web3 = new Web3('https://sepolia.infura.io/v3/6f982a16e10a4179baba45b38fcd22df');
const contractAddress = '0xc7e1A176060e0A92148845dae55F5614cDcE3Ca4'; // Replace with the actual contract address
const slot_i = 4; // Replace with the slot position of the private variable

web3.eth.getStorageAt(contractAddress, slot_i, (error, result) => {
  if (!error) {
    console.log('Private variable value:', result);
  } else {
    console.error(error);
  }
});