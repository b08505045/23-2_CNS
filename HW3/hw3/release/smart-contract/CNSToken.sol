// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./ERC20.sol";

contract CNSToken is ERC20 {
    // The following variables are OPTIONAL vanities. One does not have to include them.
    // They allow one to customise the token contract & in no way influences the core functionality.
    // Some wallets/interfaces might not even bother to look at this information.
    string public name; // fancy name: eg Simon Bucks
    uint8 public decimals; // How many decimals to show. ie. There could 1000 base units with 3 decimals. Meaning 0.980 SBX = 980 base units. It's like comparing 1 wei to 1 ether.
    string public symbol; // An identifier: eg SBX
    string public version = "1.0"; // human 0.1 standard. Just an arbitrary versioning scheme.
    address owner;

    constructor(address _owner) {
        balances[msg.sender] = 10000000000; // Give the creator all initial tokens (100000 for example)
        totalSupply = 10000000000; // Update total supply (100000 for example)
        name = "CNSToken"; // Set the name for display purposes
        decimals = 0; // Amount of decimals for display purposes
        symbol = "CNS"; // Set the symbol for display purposes
        owner = _owner;
    }

    function mint(address account, uint256 amount) external {
        require(msg.sender == owner);
        require(account != address(0), "ERC20: mint to the zero address");
        totalSupply += amount;
        balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }
}
