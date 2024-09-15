// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {ISingletonFactory, Context} from "../src/ISingletonFactory.sol";
import {SingletonFactory} from "../src/SingletonFactory.sol";
import {MockContract} from "./mocks/TestContract.t.sol";
import {InspectContext} from "./mocks/InspectContext.t.sol";

contract SingletonFactoryTest is Test {
    ISingletonFactory public factory;

    function setUp() public {
        assertEq(msg.sender, 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
        assertEq(vm.getNonce(msg.sender), 3);
        vm.startPrank(msg.sender, msg.sender);
        factory = ISingletonFactory(address(new SingletonFactory()));
        vm.stopPrank();
    }

    function create2addr(uint256 salt, bytes memory initCode) private view returns (address) {
        bytes32 codeHash = keccak256(initCode);
        bytes32 create2Hash = keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), codeHash));
        return address(uint160(uint256(create2Hash)));
    }

    function create3addr(uint256 salt) private view returns (address) {
        bytes32 codeHash = 0x9fc904680de2feb47c597aa19f58746c0a400d529ba7cfbe3cda504f5aa7914b;
        codeHash = keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), codeHash));
        address proxyAddr = address(uint160(uint256(codeHash)));
        codeHash = keccak256(abi.encodePacked(bytes2(0xd694), proxyAddr, uint8(0x01)));
        return address(uint160(uint256(codeHash)));
    }

    function assertEq(Context memory a, Context memory b) private pure {
        assertEq(a.contractAddress, b.contractAddress, "a.contractAddress != b.contractAddress");
        assertEq(a.sender, b.sender, "a.sender != b.sender");
        assertEq(a.salt, b.salt, "a.salt != b.salt");
        assertEq(a.callDepth, b.callDepth, "a.callDepth != b.callDepth");
        assertEq(a.hasInitializer, b.hasInitializer, "a.hasInitializer != b.hasInitializer");
        assertEq(a.initializer, b.initializer, "a.initializer != b.initializer");
    }

    function _inpectContext(Context memory expected, InspectContext inspector, uint256 expectedBalance) private view {
        (Context memory ctx, bool initialized, bytes memory initializer) = inspector.context();
        assertEq(address(inspector), expected.contractAddress, "address(inspector) != expected.contractAddress");
        assertEq(address(inspector).balance, expectedBalance, "address(inspector).balance != expected_balance");
        assertEq(ctx.initializer, initializer);
        assertEq(ctx.hasInitializer, initialized);
        assertEq(ctx, expected);
    }

    function _testAccount(uint256 balance) private returns (address account) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            account := keccak256(ptr, calldatasize())
            account := and(account, 0xffffffffffffffffffffffffffffffffffffffff)
            // clear the memory
            calldatacopy(ptr, calldatasize(), calldatasize())
        }
        assertEq(account.balance, 0, "test account already created");
        assertEq(vm.getNonce(account), 0, "test account already exists");
        vm.deal(account, balance);
    }

    function test_correctAddress() external view {
        assertEq(msg.sender, DEFAULT_SENDER);
        assertEq(vm.getNonce(msg.sender), 5);
        address expect = address(uint160(uint256(keccak256(hex"d6941804c8AB1F12E6bbf3894d4083f33e07309d1f3803"))));
        assertEq(address(factory), expect);
    }

    function test_create2() external {
        address sender = _testAccount(100 ether);
        uint256 salt = 0;
        bytes memory initCode = abi.encodePacked(type(MockContract).creationCode, abi.encode(address(factory), sender));
        // address expect = create2addr(salt, initCode);
        // vm.allowCheatcodes(expect);
        vm.startPrank(sender, sender);
        // console.log("   msg.sender:", sender);
        // console.log("  create2addr:", expect);

        // Reverts if the `callback` is not provided.
        vm.expectRevert(ISingletonFactory.Create2Failed.selector);
        factory.create2(salt, initCode);

        // Reverts no value is sent reverts.
        bytes memory initializer = abi.encodeCall(MockContract.initialize, ());
        {
            bytes memory innerError = abi.encodeWithSignature("Error(string)", "send money!!");
            bytes memory expectRevertMessage = abi.encodeWithSignature("InitializerReverted(bytes)", innerError);
            vm.expectRevert(expectRevertMessage);
            factory.create2(salt, initCode, initializer);
        }
        // console.logBytes(abi.encodeWithSignature("create2(uint256,bytes,bytes)", salt, initCode, initializer));

        // Should work if value is sent.
        MockContract deployed = MockContract(factory.create2{value: 1}(salt, initCode, initializer));
        assertEq(address(deployed), create2addr(salt, initCode));

        // Cannot initialize manually.
        vm.expectRevert("unauthorized");
        deployed.initialize();
    }

    function test_fuzzCreate2(uint256 salt, bytes calldata init) external {
        {
            // we assume the initializer is not the `context()` selector
            bytes4 selector;
            assembly {
                selector := shl(224, calldataload(sub(init.offset, 28)))
            }
            vm.assume(selector != InspectContext.context.selector);
        }
        address sender = _testAccount(100 ether);
        bytes memory initCode = abi.encodePacked(type(InspectContext).creationCode, abi.encode(address(factory)));
        vm.startPrank(sender, sender);

        Context memory ctx = Context({
            sender: sender,
            contractAddress: create2addr(salt, initCode),
            callDepth: 0,
            hasInitializer: false,
            initializer: hex"",
            salt: salt
        });
        InspectContext inspector;
        uint256 snapshotId = vm.snapshot();

        // Test `create3(uint256,bytes)`
        inspector = InspectContext(payable(factory.create2(salt, initCode)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes)` with value
        vm.revertTo(snapshotId);
        inspector = InspectContext(payable(factory.create2{value: 1 ether}(salt, initCode)));
        _inpectContext(ctx, inspector, 1 ether);

        // Test `create3(uint256,bytes,bytes)`
        vm.revertTo(snapshotId);
        ctx.hasInitializer = true;
        ctx.initializer = init;
        inspector = InspectContext(payable(factory.create2(salt, initCode, ctx.initializer)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes,bytes)` with value
        vm.revertTo(snapshotId);
        inspector = InspectContext(payable(factory.create2{value: 1 ether}(salt, initCode, ctx.initializer)));
        _inpectContext(ctx, inspector, 1 ether);
    }

    function test_fuzzCreate3(uint256 salt, bytes calldata init) external {
        bytes4 selector;
        assembly {
            selector := shl(224, calldataload(sub(init.offset, 28)))
        }
        // we assume the initializer is not the `context()` selector
        vm.assume(selector != InspectContext.context.selector);
        address sender = _testAccount(100 ether);
        bytes memory initCode = abi.encodePacked(type(InspectContext).creationCode, abi.encode(address(factory)));
        vm.startPrank(sender, sender);

        Context memory ctx = Context({
            sender: sender,
            contractAddress: create3addr(salt),
            callDepth: 0,
            hasInitializer: false,
            initializer: hex"",
            salt: salt
        });
        InspectContext inspector;
        uint256 snapshotId = vm.snapshot();

        // Test `create3(uint256,bytes)`
        inspector = InspectContext(payable(factory.create3(salt, initCode)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes)` with value
        vm.revertTo(snapshotId);
        inspector = InspectContext(payable(factory.create3{value: 1 ether}(salt, initCode)));
        _inpectContext(ctx, inspector, 1 ether);

        // Test `create3(uint256,bytes,bytes)`
        vm.revertTo(snapshotId);
        ctx.hasInitializer = true;
        ctx.initializer = init;
        inspector = InspectContext(payable(factory.create3(salt, initCode, ctx.initializer)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes,bytes)` with value
        vm.revertTo(snapshotId);
        inspector = InspectContext(payable(factory.create3{value: 1 ether}(salt, initCode, ctx.initializer)));
        _inpectContext(ctx, inspector, 1 ether);
    }
}
