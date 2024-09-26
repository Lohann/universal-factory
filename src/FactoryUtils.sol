// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IUniversalFactory} from "./UniversalFactory.sol";

library FactoryUtils {
    // Create3Proxy creation code
    // 0x763318602e57363d3d37363d34f080915215602e57f35bfd6017526460203d3d7360a01b33173d5260306007f3:
    //     0x00  0x67  0x763318602e..  PUSH23 0x3318.. 0x3318602e57363d3d37363d34f080915215602e57f35bfd
    //     0x01  0x3d  0x3d            PUSH1 0x58      23 0x3318602e57363d3d37363d34f080915215602e57f35bfd
    //     0x01  0x3d  0x3d            MSTORE
    //     0x03  0x52  0x5260203d3d..  PUSH5 0x60203.. 0x60203d3d73
    //     0x04  0xf3  0x6008          PUSH1 0xa0      160 0x60203d3d73
    //     0x05  0x60  0x6018          SHL             0x60203d3d730000000000000000000000000000000000000000
    //     0x06  0x3d  0x3d            CALLER          addr 0x60203d3d730000000000000000000000000000000000000000
    //     0x08  0xf3  0xf3            OR              0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    //     0x09  0x60  0x6018          RETURNDATASIZE  0 0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    //     0x04  0xf3  0x6008          PUSH1 0x30      48
    //     0x04  0xf3  0x6008          PUSH1 0x07      7 48
    //     0x14  0x3d  0x3d            RETURN
    bytes internal constant PROXY_INITCODE =
        hex"763318602e57363d3d37363d34f080915215602e57f35bfd6017526460203d3d7360a01b33173d5260306007f3";
    bytes32 internal constant PROXY_INITCODE_HASH = keccak256(PROXY_INITCODE);

    /**
     * @dev Compute the create2 address of an contract created by `UniversalFactory`.
     */
    function computeCreateAddress(IUniversalFactory factory, uint256 nonce) internal pure returns (address addr) {
        assembly ("memory-safe") {
            nonce := or(nonce, shl(7, iszero(nonce)))
            // Cache the free memory pointer.
            let free_ptr := mload(0x40)
            {
                mstore(0x14, factory)
                mstore(0x00, 0xd694)
                mstore8(0x34, nonce)
                addr := shr(96, shl(96, keccak256(30, 23)))
            }
            // Restore the free memory pointer.
            mstore(0x40, free_ptr)
        }
    }

    /**
     * @dev Compute the create2 address of an contract created by `UniversalFactory`.
     */
    function computeCreate2Address(IUniversalFactory factory, uint256 salt, bytes memory initcode)
        internal
        pure
        returns (address)
    {
        return computeCreate2Address(factory, salt, keccak256(initcode));
    }

    /**
     * @dev Compute the create2 address of an contract created by `UniversalFactory`.
     */
    function computeCreate2Address(IUniversalFactory factory, uint256 salt, bytes32 initcodeHash)
        internal
        pure
        returns (address addr)
    {
        // The code below is equivalent to the following Solidity code:
        // ```solidity
        // bytes32 create2hash = keccak256(abi.encodePacked(uint8(0xff), address(factory), salt, initcodeHash));
        // return address(uint160(uint256(create2hash)));
        // ```
        assembly ("memory-safe") {
            // Cache the free memory pointer.
            let free_ptr := mload(0x40)
            {
                mstore(0x00, factory)
                mstore8(11, 0xff)
                mstore(0x20, salt)
                mstore(0x40, initcodeHash)
                addr := shr(96, shl(96, keccak256(11, 85)))
            }
            // Restore the free memory pointer.
            mstore(0x40, free_ptr)
        }
    }

    /**
     * @dev Compute the create3 salt.
     */
    function computeCreate3Salt(address deployer, uint256 salt) internal pure returns (bytes32 create3salt) {
        // The code below is equivalent to the Solidity code:
        // ```solidity
        // create3salt = keccak256(abi.encodePacked(deployer, salt));
        // ```
        assembly ("memory-safe") {
            mstore(0x00, deployer)
            mstore(0x20, salt)
            create3salt := keccak256(12, 52)
        }
    }

    /**
     * @dev Compute the create3 address of an contract created by `UniversalFactory`.
     */
    function computeCreate3Address(IUniversalFactory factory, address deployer, uint256 salt)
        internal
        pure
        returns (address addr)
    {
        // The code below is equivalent to the following Solidity code:
        // ```solidity
        // salt = keccak256(abi.encodePacked(deployer, salt));
        // address create2addr = computeCreate2Address(factory, salt, PROXY_INITCODE_HASH);
        // bytes32 create3hash = keccak256(abi.encodePacked(bytes2(0xd694), create2addr, uint8(0x01)));
        // return address(uint160(uint256(create3hash)));
        // ```
        assembly ("memory-safe") {
            // Compute keccak256(abi.encodePacked(deployer, salt));
            mstore(0x00, deployer)
            mstore(0x20, salt)
            salt := keccak256(12, 52)

            // Cache the free memory pointer.
            let free_ptr := mload(0x40)
            {
                mstore(0x00, factory)
                mstore8(11, 0xff)
                mstore(0x20, salt)
                mstore(0x40, 0xda812570be8257354a14ed469885e4d206be920835861010301b25f5c180427a)
                mstore(0x14, keccak256(11, 85))
                mstore(0x00, 0xd694)
                mstore8(0x34, 0x01)
                addr := shr(96, shl(96, keccak256(30, 23)))
            }
            // Restore the free memory pointer.
            mstore(0x40, free_ptr)
        }
    }
}
