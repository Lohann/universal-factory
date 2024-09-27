// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {Vm} from "forge-std/Vm.sol";
import {IUniversalFactory, UniversalFactory} from "@universal-factory/UniversalFactory.sol";
import {FactoryUtils} from "@universal-factory/FactoryUtils.sol";
import {Owned} from "./Owned.sol";
import {TestUtils} from "../helpers/TestUtils.sol";

contract OwnedTest is Test {
    using FactoryUtils for IUniversalFactory;

    address internal constant FACTORY_DEPLOYER = 0xd62D24A6724d8eFddA1Cff1D65Ea5080782eeFA9;
    IUniversalFactory internal constant FACTORY = IUniversalFactory(
        address(uint160(uint256(keccak256(abi.encodePacked(uint16(0xd694), FACTORY_DEPLOYER, uint8(0x80))))))
    );

    constructor() {
        vm.deal(FACTORY_DEPLOYER, 100 ether);
        assertEq(vm.getNonce(FACTORY_DEPLOYER), 0);
        vm.prank(FACTORY_DEPLOYER, FACTORY_DEPLOYER);
        address factory = address(new UniversalFactory());
        assertEq(factory, address(FACTORY));
    }

    /**
     * @dev Only the `UniversalFactory` can create the contract.
     */
    function test_failWrongSender(address owner) external {
        vm.expectRevert("can only be created using Universal Factory");
        new Owned(owner);
    }

    /**
     * @dev The caller must be the OWNER account.
     */
    function test_failWrongOwner(bytes32 salt, address owner) external {
        address sender = TestUtils.testAccount(100 ether);
        bytes memory creationCode = bytes.concat(type(Owned).creationCode, abi.encode(owner));
        vm.prank(sender, sender);
        vm.expectRevert(IUniversalFactory.Create2Failed.selector);
        FACTORY.create2(salt, creationCode);
    }

    /**
     * @dev Must fail if don't provide an `uint256` argument.
     */
    function test_failWithoutArguments(bytes32 salt) external {
        address owner = TestUtils.testAccount(100 ether);
        bytes memory creationCode = bytes.concat(type(Owned).creationCode, abi.encode(owner));
        vm.prank(owner, owner);
        vm.expectRevert(IUniversalFactory.Create2Failed.selector);
        Owned(FACTORY.create2(salt, creationCode));
    }

    /**
     * @dev Only works when the provided owned == ctx.sender, and provide an UINT256 argument.
     */
    function test_create2Works(bytes32 salt, uint256 value) external {
        address owner = TestUtils.testAccount(100 ether);
        bytes memory creationCode = bytes.concat(type(Owned).creationCode, abi.encode(owner));
        bytes memory arguments = abi.encode(value);
        vm.prank(owner, owner);
        Owned owned = Owned(FACTORY.create2(salt, creationCode, arguments));
        assertEq(owned.owner(), owner);
        assertEq(owned.value(), value);
        assertEq(address(owned), FACTORY.computeCreate2Address(salt, keccak256(creationCode)));
    }

    /**
     * @dev Only works when the provided owned == ctx.sender, and provide an UINT256 argument.
     */
    function test_create3Works(bytes32 salt, uint256 value) external {
        address owner = TestUtils.testAccount(100 ether);
        bytes memory creationCode = bytes.concat(type(Owned).creationCode, abi.encode(owner));
        bytes memory arguments = abi.encode(value);
        vm.prank(owner, owner);
        Owned owned = Owned(FACTORY.create3(salt, creationCode, arguments));
        assertEq(owned.owner(), owner);
        assertEq(owned.value(), value);
        assertEq(address(owned), FACTORY.computeCreate3Address(owner, salt));
    }
}
