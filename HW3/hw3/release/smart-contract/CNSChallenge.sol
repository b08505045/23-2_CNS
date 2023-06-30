// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./CNSToken.sol";
import "./CNSWallet.sol";

// interfaces that will be used
interface IFlashLoanReceiver {
    // Note: approve lender to tranfer your token in order to return the fund.
    function execute(
        address tokenAddr,
        address lender,
        uint256 amount
    ) external returns (bool);
}

// the main challenge contract
contract CNSChallenge {
    address payable public owner;
    CNSToken public cnsToken;
    CNSWallet public cnsWallet;

    struct Student {
        mapping(uint => bool) solved;
        uint score;
    }

    // studentID: lowercase and number. ex: r10922000
    mapping(string => Student) students;

    // challenge 0: call me, 2 points
    function callMeFirst(string calldata studentID) public {
        uint challengeID = 0;
        uint point = 2;
        require(students[studentID].solved[challengeID] != true);
        students[studentID].solved[challengeID] = true;
        students[studentID].score += point;
    }

    // challenge 1: bribe me ether, 3 points
    function bribeMe(string calldata studentID) public payable {
        uint challengeID = 1;
        uint point = 3;
        require(students[studentID].solved[challengeID] != true);
        require(msg.value == 1 ether);
        students[studentID].solved[challengeID] = true;
        students[studentID].score += point;
    }

    // challenge 2: guess random number, 7 points
    uint16 private next;
    uint public numberOfTry = 0;

    function random() internal returns (uint16) {
        next = next * 8191 + 12347;
        numberOfTry += 1;
        return next;
    }

    function guessRandomNumber(
        string calldata studentID,
        uint16 numberGuessed
    ) public {
        uint challengeID = 2;
        uint point = 7;
        require(students[studentID].solved[challengeID] != true);

        uint16 randomNumber = random();
        if (numberGuessed == randomNumber) {
            students[studentID].solved[challengeID] = true;
            students[studentID].score += point;
        }
    }

    // challenge 3: easy reentry, 8 points
    uint16 c3Flag = 0;

    function reentry(string calldata studentID) public {
        uint challengeID = 3;
        uint point = 8;
        require(students[studentID].solved[challengeID] != true);
        c3Flag += 1;
        msg.sender.call("");
        if (c3Flag == 2) {
            students[studentID].solved[challengeID] = true;
            students[studentID].score += point;
        }
        c3Flag = 0;
    }

    // challenge 4: prove that you have enough CNS tokens but not using flash loan!? 10 points
    uint8 public flashloaning = 0;

    function flashloan(uint256 amount) public {
        require(amount <= cnsToken.balanceOf(address(this)));
        flashloaning += 4;
        cnsToken.transfer(msg.sender, amount);
        require(
            IFlashLoanReceiver(msg.sender).execute(
                address(cnsToken),
                address(this),
                amount
            ),
            "Flash loan execute error!"
        );
        require(
            cnsToken.transferFrom(msg.sender, address(this), amount),
            "You need to return fund!"
        );
        flashloaning -= 4;
    }

    function giveMeToken(string calldata studentID) public {
        uint challengeID = 4;
        uint point = 10;
        require(flashloaning == 0, "You are doing flashloan!");
        require(students[studentID].solved[challengeID] != true);
        if (cnsToken.balanceOf(msg.sender) >= 10000) {
            students[studentID].solved[challengeID] = true;
            students[studentID].score += point;
            // give you one CNS token as reward!
            cnsToken.transfer(msg.sender, 1);
        }
    }

    // bonus challenge: steal the ethers, 10 points
    // note: please do not steal CNS tokens more than you need, for others to
    // work on this challenge, thanks
    function setupWallet(bytes memory initializer) public {
        if (initializer.length > 0) {
            require(
                selectorEq(initializer, CNSWallet.setup.selector),
                "invalid initializer"
            );

            bool success;
            address to = address(cnsWallet);
            assembly {
                // make a call to cnsWallet with initializer as calldata
                success := call(
                    gas(),
                    to,
                    0,
                    add(initializer, 0x20),
                    mload(initializer),
                    0,
                    0
                )
            }
            require(success, "initilization failed");
        }
    }

    function claimRewards(string calldata studentID) public {
        uint challengeID = 5;
        uint point = 10;
        require(students[studentID].solved[challengeID] != true);

        if (cnsToken.balanceOf(msg.sender) >= 200000000) {
            students[studentID].solved[challengeID] = true;
            students[studentID].score += point;
        }
    }

    function selectorEq(
        bytes memory data,
        bytes4 value
    ) internal pure returns (bool res) {
        // return if value == data[:4] (function selector in `data`)
        // in solc >= 0.8.0, this can be simply done by `return bytes4(data[:4]) == value`
        assembly {
            res := eq(mload(add(data, 0x20)), value)
        }
    }

    // utilities
    function getScore(string calldata studentID) public view returns (uint) {
        return students[studentID].score;
    }

    function getSolvedStatus(
        string calldata studentID
    ) public view returns (bool[] memory) {
        bool[] memory ret = new bool[](6);
        for (uint i = 0; i < 6; i++) {
            ret[i] = students[studentID].solved[i];
        }
        return ret;
    }

    // contract initialization
    constructor() {
        owner = msg.sender;
        cnsToken = new CNSToken(msg.sender);
        cnsWallet = new CNSWallet();
        cnsToken.transfer(address(cnsWallet), 9900000000);
        next = uint16(
            bytes2(
                keccak256(
                    abi.encodePacked(
                        blockhash(block.number - 1),
                        block.timestamp
                    )
                )
            )
        );
    }

    function destroy() public {
        require(msg.sender == owner);
        selfdestruct(owner);
    }
}
