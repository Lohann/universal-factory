// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {ISingletonFactory, Context, CreateKind} from "../src/ISingletonFactory.sol";
import {SingletonFactory} from "../src/SingletonFactory.sol";
import {MockContract} from "./mocks/TestContract.t.sol";
import {NestedCreate} from "./mocks/NestedCreate.t.sol";
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

    function create2addr(uint256 salt, bytes32 codeHash) private view returns (address) {
        bytes32 create2Hash = keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), codeHash));
        return address(uint160(uint256(create2Hash)));
    }

    function create2addr(uint256 salt, bytes memory initCode) private view returns (address) {
        return create2addr(salt, keccak256(initCode));
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
        assertEq(a.value, b.value, "a.value != b.value");
        assertEq(a.salt, b.salt, "a.salt != b.salt");
        assertEq(a.callDepth, b.callDepth, "a.callDepth != b.callDepth");
        assertEq(a.hasCallback, b.hasCallback, "a.hasCallback != b.hasCallback");
        assertEq(a.callbackSelector, b.callbackSelector, "a.callbackSelector != b.callbackSelector");
        assertEq(a.data, b.data, "a.data != b.data");
    }

    function _inpectContext(Context memory expected, InspectContext inspector, uint256 expectedBalance) private view {
        (Context memory ctx, bool initialized, bytes memory data) = inspector.context();
        assertEq(address(inspector), expected.contractAddress, "address(inspector) != expected.contractAddress");
        assertEq(address(inspector).balance, expectedBalance, "address(inspector).balance != expected_balance");
        assertEq(ctx.data, data);
        assertEq(ctx.hasCallback, initialized);
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
        uint256 salt = 0x7777777777777777777777777777777777777777777777777777777777777777;
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
        console.logBytes(initializer);
        {
            bytes memory innerError = abi.encodeWithSignature("Error(string)", "send money!!");
            bytes memory expectRevertMessage = abi.encodeWithSignature("CallbackFailed(bytes)", innerError);
            vm.expectRevert(expectRevertMessage);
            factory.create2(salt, initCode, "", initializer);
        }

        // Should work if value is sent.
        MockContract deployed = MockContract(factory.create2{value: 1}(salt, initCode, "", initializer));
        assertEq(address(deployed), create2addr(salt, initCode));

        // Cannot initialize manually.
        vm.expectRevert("unauthorized");
        deployed.initialize();
    }

    function test_fuzzCreate2(uint256 salt, bytes calldata init) external {
        // we assume the initializer is not the `context()` selector
        bytes4 selector;
        assembly {
            selector := shl(224, calldataload(sub(init.offset, 28)))
        }
        vm.assume(selector != InspectContext.context.selector);

        address sender = _testAccount(100 ether);
        bytes memory initCode = abi.encodePacked(type(InspectContext).creationCode, abi.encode(address(factory)));
        vm.startPrank(sender, sender);

        Context memory ctx = Context({
            contractAddress: create2addr(salt, initCode),
            sender: sender,
            callDepth: 1,
            kind: CreateKind.CREATE2,
            hasCallback: false,
            callbackSelector: bytes4(0),
            value: 0,
            salt: salt,
            data: hex""
        });
        InspectContext inspector;
        uint256 snapshotId = vm.snapshot();

        // Test `create3(uint256,bytes)`
        inspector = InspectContext(payable(factory.create2(salt, initCode)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        inspector = InspectContext(payable(factory.create2{value: 1 ether}(salt, initCode)));
        _inpectContext(ctx, inspector, 1 ether);

        // Test `create3(uint256,bytes,bytes)`
        vm.revertTo(snapshotId);
        ctx.hasCallback = true;
        ctx.callbackSelector = selector;
        ctx.data = init;
        ctx.value = 0;
        inspector = InspectContext(payable(factory.create2(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        inspector = InspectContext(payable(factory.create2{value: 1 ether}(salt, initCode, ctx.data, ctx.data)));
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
            contractAddress: create3addr(salt),
            sender: sender,
            callDepth: 1,
            kind: CreateKind.CREATE3,
            hasCallback: false,
            callbackSelector: bytes4(0),
            value: 0,
            salt: salt,
            data: hex""
        });
        InspectContext inspector;
        uint256 snapshotId = vm.snapshot();

        // Test `create3(uint256,bytes)`
        inspector = InspectContext(payable(factory.create3(salt, initCode)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        inspector = InspectContext(payable(factory.create3{value: 1 ether}(salt, initCode)));
        _inpectContext(ctx, inspector, 1 ether);

        // Test `create3(uint256,bytes,bytes)`
        vm.revertTo(snapshotId);
        ctx.hasCallback = true;
        ctx.callbackSelector = selector;
        ctx.data = init;
        ctx.value = 0;
        inspector = InspectContext(payable(factory.create3(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        inspector = InspectContext(payable(factory.create3{value: 1 ether}(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 1 ether);
    }

    /**
     * Test the `context()` when calling the `SingletonFactory` from inside an created contract.
     */
    function test_neastedCreate2() external {
        address sender = _testAccount(100_000 ether);
        bytes memory initCode = abi.encodePacked(type(NestedCreate).creationCode, abi.encode(address(factory)));
        bytes32 codeHash = keccak256(initCode);
        vm.startPrank(sender, sender);
        uint256 maxDepth = 91;

        // Prepare the data for the child contracts.
        uint256[] memory nestedList = new uint256[](maxDepth);
        for (uint256 i = 0; i < maxDepth; i++) {
            nestedList[i] = maxDepth - i;
        }
        bytes memory params = abi.encode(nestedList);

        uint256 salt = 0x0101010101010101010101010101010101010101010101010101010101010101;
        bytes memory callback = abi.encodeCall(NestedCreate.validateContext, ());

        // Stop gas metering otherwise the following call fails with `EvmError: OutOfGas`.
        vm.pauseGasMetering();
        // Deploy the contract
        NestedCreate deployed = NestedCreate(payable(factory.create2(salt, initCode, params, callback)));
        // factory.create2(salt, initCode, params);
        vm.resumeGasMetering();

        Context memory ctx = Context({
            contractAddress: sender,
            sender: address(0),
            callDepth: 0,
            kind: CreateKind.CREATE2,
            hasCallback: true,
            callbackSelector: NestedCreate.validateContext.selector,
            value: 0,
            salt: 0,
            data: params
        });
        bytes32 deployedCodeHash;
        assembly {
            deployedCodeHash := extcodehash(deployed)
        }

        // Check the context of the child contracts.
        for (uint256 i = 0; i < maxDepth; i++) {
            require(address(deployed).code.length > 0, "contract not exists");

            // Update the `ctx` for the next child contract.
            ctx.callDepth += 1;
            ctx.salt += salt;
            ctx.sender = ctx.contractAddress;
            ctx.contractAddress = create2addr(ctx.salt, codeHash);
            ctx.data = params;

            // prepare the `ctx.data` for the next child contract.
            assembly {
                mstore(add(params, 0x40), sub(maxDepth, i))
                mstore(params, shl(5, sub(add(maxDepth, 2), i)))
            }

            // Compare the context of the contract with the expected context.
            (Context memory actualCtx, bool initialized, NestedCreate child) = deployed.context();
            assertEq(actualCtx, ctx);
            assertEq(initialized, true);

            // Check `child` codehash
            if (address(child) != address(0)) {
                bytes32 childCodeHash;
                assembly {
                    childCodeHash := extcodehash(child)
                }
                assertEq(deployedCodeHash, childCodeHash, "child and contract must have the same codehash");
            }

            // Move to the next child contract.
            deployed = child;
        }

        // The last contract should not have any child contracts.
        require(address(deployed) == address(0), "last child must be empty");
    }
}
