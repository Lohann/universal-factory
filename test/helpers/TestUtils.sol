// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";
import {IUniversalFactory} from "@universal-factory/IUniversalFactory.sol";

library TestUtils {
    // Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /**
     * @dev Create a test account with the given balance.
     */
    function testAccount(uint256 balance) internal returns (address account) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            account := keccak256(ptr, calldatasize())
            account := and(account, 0xffffffffffffffffffffffffffffffffffffffff)
            // clear the memory
            calldatacopy(ptr, calldatasize(), calldatasize())
        }
        require(vm.getNonce(account) == 0, "account already exists");
        require(account.balance == 0, "account already funded");
        vm.deal(account, balance);
    }
}
