// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {VmSafe} from "forge-std/Vm.sol";
import {Test, console} from "forge-std/Test.sol";
import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";
import {SingletonFactory} from "../../src/SingletonFactory.sol";

contract NestedCreate {
    VmSafe internal constant VM = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    ISingletonFactory private immutable FACTORY;
    Context private _ctx;
    uint256 private _constructorCallValue;
    bool private _initialized;
    NestedCreate private _child;

    constructor(ISingletonFactory factory) payable {
        FACTORY = factory;
        Context memory ctx = factory.context();
        console.log("       address(this):", address(this));
        console.log(" ctx.contractAddress:", ctx.contractAddress);
        console.log("          ctx.sender:", ctx.sender);
        console.log("       ctx.callDepth:", ctx.callDepth);
        console.log("            ctx.kind:", uint256(ctx.kind));
        console.log("     ctx.hasCallback:", ctx.hasCallback);
        console.log("ctx.callbackSelector:", VM.toString(bytes32(ctx.callbackSelector)));
        console.log("            ctx.salt:", VM.toString(bytes32(ctx.salt)));
        console.log("            ctx.data:", ctx.data.length);
        console.log("");
        // console.log("            ctx.data:", VM.toString(ctx.data));

        if (ctx.hasCallback) {
            require(msg.value == 0, "cannot send value to constructor when using callback");
        }
        require(ctx.data.length == 0 || ctx.data.length > 32, "invalid ctx.data length");
        _constructorCallValue = msg.value;
        _ctx = ctx;
        _initialized = false;
        if (ctx.data.length > 0) {
            _child = NestedCreate(payable(_create(address(factory), ctx.data)));
        }
    }

    function _create(address factory, bytes memory data) private returns (address) {
        (uint256 callDepth, bytes memory callData) = abi.decode(data, (uint8, bytes));
        require(callDepth == _ctx.callDepth, "callDepth != _ctx.callDepth");
        if (callData.length > 0) {
            (bool success, bytes memory result) = factory.call(callData);
            if (!success) {
                console.log("             error:", VM.toString(result));
                assembly {
                    revert(add(result, 0x20), mload(result))
                }
            }
            return abi.decode(result, (address));
        }
        return address(0);
    }

    function context() external view returns (Context memory, bool, NestedCreate) {
        require(msg.sender != address(FACTORY), "factory cannot call context");
        require(_initialized == _ctx.hasCallback, "not initialized");
        return (_ctx, _initialized, _child);
    }

    fallback() external payable {
        require(msg.sender == address(FACTORY), "only factory can call fallback");
        require(_initialized == false, "already initialized");
        require(_ctx.hasCallback, "no callback expected");
        _initialized = true;
        if (_ctx.data.length > 0) {
            _child = NestedCreate(payable(_create(address(FACTORY), _ctx.data)));
        }
    }

    receive() external payable {
        require(msg.sender == address(FACTORY), "only factory can call fallback");
        require(_initialized == false, "already initialized");
        require(_ctx.hasCallback, "no callback expected");
        _initialized = true;
        if (_ctx.data.length > 0) {
            _child = NestedCreate(payable(_create(address(FACTORY), _ctx.data)));
        }
    }
}
