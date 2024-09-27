// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Minimal contract used in examples and tests.
contract MyContract {
    uint256 private _value;

    function value() external view returns (uint256) {
        return _value;
    }

    function setValue(uint256 newValue) external {
        _value = newValue;
    }
}
