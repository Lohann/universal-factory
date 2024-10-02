// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {Vm} from "forge-std/Vm.sol";
import {UniversalFactory} from "../src/UniversalFactory.sol";
import {CreateKind, Context, IUniversalFactory} from "../src/IUniversalFactory.sol";
import {FactoryUtils} from "../src/FactoryUtils.sol";
import {ReservedContract} from "./helpers/ReservedContract.t.sol";
import {NestedCreate} from "./helpers/NestedCreate.t.sol";
import {Inspector} from "./helpers/Inspector.t.sol";
import {TestUtils} from "./helpers/TestUtils.sol";

contract UniversalFactoryTest is Test {
    using FactoryUtils for IUniversalFactory;

    IUniversalFactory public factory;

    function setUp() public {
        assertEq(msg.sender, 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
        assertEq(vm.getNonce(msg.sender), 3);
        vm.startPrank(msg.sender, msg.sender);
        factory = IUniversalFactory(address(new UniversalFactory()));
        vm.stopPrank();
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

    function _inpectContext(Context memory expected, Inspector inspector, uint256 expectedBalance) private view {
        (Context memory ctx, bool initialized, bytes memory data) = inspector.context();
        assertEq(address(inspector), expected.contractAddress, "address(inspector) != expected.contractAddress");
        assertEq(address(inspector).balance, expectedBalance, "address(inspector).balance != expected_balance");
        assertEq(ctx.data, data);
        assertEq(ctx.hasCallback, initialized);
        assertEq(ctx, expected);
    }

    function test_correctAddress() external view {
        assertEq(msg.sender, DEFAULT_SENDER);
        assertEq(vm.getNonce(msg.sender), 5);
        address expect = address(uint160(uint256(keccak256(hex"d6941804c8AB1F12E6bbf3894d4083f33e07309d1f3803"))));
        assertEq(address(factory), expect);
    }

    function test_create2() external {
        address sender = TestUtils.testAccount(100 ether);
        bytes32 salt = 0x7777777777777777777777777777777777777777777777777777777777777777;
        bytes memory initCode =
            abi.encodePacked(type(ReservedContract).creationCode, abi.encode(address(factory), sender));
        vm.startPrank(sender, sender);

        // Reverts if the `callback` is not provided.
        vm.expectRevert(IUniversalFactory.Create2Failed.selector);
        factory.create2(salt, initCode);

        // Reverts no value is sent reverts.
        bytes memory initializer = abi.encodeCall(ReservedContract.initialize, ());
        console.logBytes(initializer);
        {
            bytes memory innerError = abi.encodeWithSignature("Error(string)", "must send funds");
            bytes memory expectRevertMessage = abi.encodeWithSignature("CallbackFailed(bytes)", innerError);
            vm.expectRevert(expectRevertMessage);
            factory.create2(salt, initCode, "", initializer);
        }

        // Should work if value is sent.
        ReservedContract deployed = ReservedContract(factory.create2{value: 1}(salt, initCode, "", initializer));
        assertEq(address(deployed), factory.computeCreate2Address(salt, initCode));

        // Cannot initialize manually.
        vm.expectRevert("unauthorized");
        deployed.initialize();
    }

    function test_fuzzCreate2(bytes32 salt, bytes calldata init) external {
        // we assume the initializer is not the `context()` selector
        bytes4 selector;
        assembly {
            selector := shl(224, calldataload(sub(init.offset, 28)))
        }
        vm.assume(selector != Inspector.context.selector);

        // Setup the test environment.
        address sender = TestUtils.testAccount(100 ether);
        bytes memory initCode = abi.encodePacked(type(Inspector).creationCode, abi.encode(address(factory)));
        bytes32 creationCodeHash = keccak256(initCode);
        bytes32 runtimeCodehash = keccak256(type(Inspector).runtimeCode);
        bytes32 callbackHash = keccak256(init);
        vm.startPrank(sender, sender);
        uint256 snapshotId = vm.snapshot();

        Context memory ctx = Context({
            contractAddress: factory.computeCreate2Address(salt, creationCodeHash),
            sender: sender,
            callDepth: 1,
            kind: CreateKind.CREATE2,
            hasCallback: false,
            callbackSelector: bytes4(0),
            value: 0,
            salt: salt,
            data: hex""
        });
        Inspector inspector;

        // Test `create3(uint256,bytes)`
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress, creationCodeHash, salt, ctx.sender, bytes32(0), runtimeCodehash, bytes32(0), 1, 0
        );
        inspector = Inspector(payable(factory.create2(salt, initCode)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress, creationCodeHash, salt, ctx.sender, bytes32(0), runtimeCodehash, bytes32(0), 1, 1 ether
        );
        inspector = Inspector(payable(factory.create2{value: 1 ether}(salt, initCode)));
        _inpectContext(ctx, inspector, 1 ether);

        // Test `create3(uint256,bytes,bytes)`
        vm.revertTo(snapshotId);
        ctx.hasCallback = true;
        ctx.callbackSelector = selector;
        ctx.data = init;
        ctx.value = 0;
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress, creationCodeHash, salt, ctx.sender, callbackHash, runtimeCodehash, callbackHash, 1, 0
        );
        inspector = Inspector(payable(factory.create2(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;

        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress,
            creationCodeHash,
            salt,
            ctx.sender,
            callbackHash,
            runtimeCodehash,
            callbackHash,
            1,
            1 ether
        );
        inspector = Inspector(payable(factory.create2{value: 1 ether}(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 1 ether);
    }

    function test_fuzzCreate3(bytes32 salt, bytes calldata init) external {
        // we assume the initializer is not the `context()` selector
        bytes4 selector;
        assembly {
            selector := shl(224, calldataload(sub(init.offset, 28)))
        }
        vm.assume(selector != Inspector.context.selector);

        // Setup the test environment.
        address sender = TestUtils.testAccount(1000 ether);
        bytes memory initCode = abi.encodePacked(type(Inspector).creationCode, abi.encode(address(factory)));
        bytes32 creationCodeHash = keccak256(initCode);
        bytes32 runtimeCodehash = keccak256(type(Inspector).runtimeCode);
        bytes32 callbackHash = keccak256(init);
        vm.startPrank(sender, sender);

        Context memory ctx = Context({
            contractAddress: factory.computeCreate3Address(sender, salt),
            sender: sender,
            callDepth: 1,
            kind: CreateKind.CREATE3,
            hasCallback: false,
            callbackSelector: bytes4(0),
            value: 0,
            salt: salt,
            data: hex""
        });
        Inspector inspector;
        uint256 snapshotId = vm.snapshot();

        // Test `create3(uint256,bytes)`
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress, creationCodeHash, salt, ctx.sender, bytes32(0), runtimeCodehash, bytes32(0), 1, 0
        );
        inspector = Inspector(payable(factory.create3(salt, initCode)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress, creationCodeHash, salt, ctx.sender, bytes32(0), runtimeCodehash, bytes32(0), 1, 1 ether
        );
        inspector = Inspector(payable(factory.create3{value: 1 ether}(salt, initCode)));
        _inpectContext(ctx, inspector, 1 ether);

        // Test `create3(uint256,bytes,bytes)`
        vm.revertTo(snapshotId);
        ctx.hasCallback = true;
        ctx.callbackSelector = selector;
        ctx.data = init;
        ctx.value = 0;
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress, creationCodeHash, salt, ctx.sender, callbackHash, runtimeCodehash, callbackHash, 1, 0
        );
        inspector = Inspector(payable(factory.create3(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 0);

        // Test `create3(uint256,bytes,bytes)` with value
        vm.revertTo(snapshotId);
        ctx.value = 1 ether;
        vm.expectEmitAnonymous(true, true, true, true, true);
        emit IUniversalFactory.ContractCreated(
            ctx.contractAddress,
            creationCodeHash,
            salt,
            ctx.sender,
            callbackHash,
            runtimeCodehash,
            callbackHash,
            1,
            1 ether
        );
        inspector = Inspector(payable(factory.create3{value: 1 ether}(salt, initCode, ctx.data, ctx.data)));
        _inpectContext(ctx, inspector, 1 ether);
    }

    /**
     * Test the `context()` when calling the `UniversalFactory` from inside an created contract.
     * obs: Stop gas metering otherwise it fails with `EvmError: OutOfGas`.
     */
    function test_neastedCreate2() external noGasMetering {
        address sender = TestUtils.testAccount(100_000 ether);
        bytes memory initCode = abi.encodePacked(type(NestedCreate).creationCode, abi.encode(address(factory)));
        bytes32 creationCodeHash = keccak256(initCode);
        bytes32 runtimeCodeHash = keccak256(type(NestedCreate).runtimeCode);
        vm.startPrank(sender, sender);
        uint256 maxDepth = 127;

        // Prepare the data for the child contracts.
        uint256[] memory nestedList = new uint256[](maxDepth);
        for (uint256 i = 0; i < maxDepth; i++) {
            nestedList[i] = maxDepth - i;
        }
        bytes memory params = abi.encode(nestedList);

        uint256 salt = 0x0101010101010101010101010101010101010101010101010101010101010101;
        bytes memory callback = abi.encodeCall(NestedCreate.validateContext, ());
        bytes32 callbackHash = keccak256(callback);

        // Record the logs and deploy the contract
        vm.recordLogs();
        NestedCreate deployed = NestedCreate(payable(factory.create2(bytes32(salt), initCode, params, callback)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(address(deployed).code, type(NestedCreate).runtimeCode, "runtime bytecode mismatch");
        assertEq(logs.length, maxDepth, "logs.length != maxDepth");

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

        // Check the context of the child contracts.
        for (uint256 i = 0; i < maxDepth; i++) {
            require(address(deployed).code.length > 0, "contract not exists");

            // Update the `ctx` for the next child contract.
            ctx.callDepth += 1;
            ctx.salt = bytes32(uint256(ctx.salt) + salt);
            ctx.sender = ctx.contractAddress;
            ctx.contractAddress = factory.computeCreate2Address(ctx.salt, creationCodeHash);
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
                assertEq(runtimeCodeHash, childCodeHash, "child and contract must have the same codehash");
            }

            // Check logs
            Vm.Log memory log = logs[maxDepth - 1 - i];
            assertEq(log.topics.length, 4, "log topics length mismatch");
            assertEq(log.topics[0], bytes32(uint256(uint160(ctx.contractAddress))), "log.contractAddress mismatch");
            assertEq(log.topics[1], creationCodeHash, "log.creationCodeHash mismatch");
            assertEq(log.topics[2], bytes32(ctx.salt), "log.salt mismatch");
            assertEq(log.topics[3], bytes32(uint256(uint160(ctx.sender))), "log.sender mismatch");
            assertEq(
                log.data,
                abi.encode(keccak256(ctx.data), runtimeCodeHash, callbackHash, ctx.callDepth, ctx.value),
                "log.data mismatch"
            );

            // Move to the next child contract.
            deployed = child;
        }

        // The last contract should not have any child contracts.
        require(address(deployed) == address(0), "last child must be empty");
    }

    /**
     * Test the `context()` when calling the `UniversalFactory` from inside an created contract.
     * obs: Stop gas metering otherwise it fails with `EvmError: OutOfGas`.
     */
    function test_maxDepth() external noGasMetering {
        address sender = TestUtils.testAccount(100_000 ether);
        bytes memory initCode = abi.encodePacked(type(NestedCreate).creationCode, abi.encode(address(factory)));
        vm.startPrank(sender, sender);
        uint256 maxDepth = 128;

        // Prepare the data for the child contracts.
        uint256[] memory nestedList = new uint256[](maxDepth);
        for (uint256 i = 0; i < maxDepth; i++) {
            nestedList[i] = maxDepth - i;
        }
        bytes memory params = abi.encode(nestedList);
        bytes memory callback = abi.encodeCall(NestedCreate.validateContext, ());

        // Must fail when the depth is greater than 127.
        vm.expectRevert(IUniversalFactory.Create2Failed.selector);
        NestedCreate(payable(factory.create2(bytes32(uint256(0x0101)), initCode, params, callback)));
    }
}
