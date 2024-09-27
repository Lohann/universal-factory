// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IUniversalFactory} from "./UniversalFactory.sol";

/**
 * @title A library with helper methods for compute `CREATE2` and `CREATE3` addresses.
 * @author Lohann Paterno Coutinho Ferreira <developer@lohann.dev>
 */
library FactoryUtils {
    /**
     * @notice The `Create3Proxy` is a contract that proxies the creation of another contract
     * @dev If this code is deployed using CREATE2 it can be used to decouple `creationCode` from the child contract address.
     *
     * Create3Proxy creation code
     * 0x763318602e57363d3d37363d47f080915215602e57f35bfd602b52336014526460203d3d733d526030601bf3:
     *     0x00  0x763318602e..  PUSH23 0x3318.. 0x3318602e57363d3d37363d47f080915215602e57f35bfd
     *     0x18  0x602b          PUSH1 0x2b      43 0x3318602e57363d3d37363d47f080915215602e57f35bfd
     *     0x1a  0x52            MSTORE
     *     0x1b  0x33            CALLER          addr
     *     0x1c  0x6014          PUSH1 20        20 addr
     *     0x1f  0x52            MSTORE
     *     0x25  0x6460203d3d73  PUSH5 0x6020..  0x60203d3d73
     *     0x26  0x3d            RETURNDATASIZE  0 0x60203d3d73
     *     0x27  0x52            MSTORE
     *     0x29  0x6030          PUSH1 48        48
     *     0x2a  0x601b          PUSH1 27        27 48
     *     0x2b  0xf3            RETURN
     *
     * Create3Proxy runtime code, where `XXXX..` is the Universal Factory contract address.
     * 0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX3318602e57363d3d37363d47f080915215602e57f35bfd
     *     0x00  0x6020          PUSH1 32        32
     *     0x02  0x3d            RETURNDATASIZE  0 32
     *     0x03  0x3d            RETURNDATASIZE  0 0 32
     *     0x04  0x74XXXXXX..    PUSH20 XXXXXXX  factory 0 0 32
     *     0x19  0x33            CALLER          caller factory 0 0 32
     *     0x1a  0x18            XOR             invalid 0 0 32
     *     0x1b  0x602e          PUSH1 0x2e      46 invalid 0 0 32
     * ,=< 0x1d  0x57            JUMPI           0 0 32
     * |   0x1e  0x36            CALLDATASIZE    cls 0 0 32
     * |   0x1f  0x3d            RETURNDATASIZE  0 cls 0 0 32
     * |   0x20  0x3d            RETURNDATASIZE  0 0 cls 0 0 32
     * |   0x21  0x37            CALLDATACOPY    0 0 32
     * |   0x22  0x36            CALLDATASIZE    cls 0 0 32
     * |   0x23  0x3d            RETURNDATASIZE  0 cls 0 0 32
     * |   0x24  0x47            SELFBALANCE     val 0 cls 0 0 32
     * |   0x25  0xf0            CREATE          addr 0 0 32
     * |   0x26  0x80            DUP1            addr addr 0 0 32
     * |   0x27  0x91            SWAP2           0 addr addr 0 32
     * |   0x28  0x52            MSTORE          addr 0 32
     * |   0x29  0x16            ISZERO          fail 0 32
     * |   0x2a  0x602e          PUSH1 0x2e      46 fail 0 32
     * |=< 0x2c  0x57            JUMPI           0 32
     * |   0x2d  0xf3            RETURN
     * `=> 0x2e  0x5b            JUMPDEST
     *     0x2f  0xfd            REVERT
     */
    bytes internal constant PROXY_INITCODE =
        hex"763318602e57363d3d37363d47f080915215602e57f35bfd602b52336014526460203d3d733d526030601bf3";

    /**
     * @dev Create3Proxy creation code hash
     * PROXY_INITCODE_HASH == keccak256(PROXY_INITCODE)
     */
    bytes32 internal constant PROXY_INITCODE_HASH = 0x0281a97663cf81306691f0800b13a91c4d335e1d772539f127389adae654ffc6;

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
    function computeCreate2Address(IUniversalFactory factory, bytes32 salt, bytes memory initcode)
        internal
        pure
        returns (address)
    {
        return computeCreate2Address(factory, salt, keccak256(initcode));
    }

    /**
     * @dev Compute the create2 address of an contract created by `UniversalFactory`.
     */
    function computeCreate2Address(IUniversalFactory factory, bytes32 salt, bytes32 initcodeHash)
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
     * @dev Compute the create3 salt, this is used to guarantee the uniqueness of the create3 address per deployer.
     */
    function computeCreate3Salt(address deployer, bytes32 salt) internal pure returns (bytes32 create3salt) {
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
    function computeCreate3Address(IUniversalFactory factory, address deployer, bytes32 salt)
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
                mstore(0x40, PROXY_INITCODE_HASH)
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
