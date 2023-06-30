// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title CNSWallet - A multisignature wallet
 * @dev Simplified from GnosisSafe (https://github.com/safe-global/safe-contracts)
 */
contract CNSWallet {
    address[] owners;
    uint256 threshold;
    bool initialized = false;

    event CNSWalletSetup(
        address indexed initiator,
        address[] owners,
        uint256 threshold
    );

    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address setupModule,
        bytes memory setupData
    ) public returns (bool success) {
        for (uint256 i = 0; i < _owners.length; i++) {
            owners[i] = _owners[i];
        }
        threshold = _threshold;

        assembly {
            success := delegatecall(
                gas(),
                setupModule,
                add(setupData, 0x20),
                mload(setupData),
                0,
                0
            )
        }
        require(success, "setup module failed");

        emit CNSWalletSetup(msg.sender, _owners, _threshold);
    }
}
