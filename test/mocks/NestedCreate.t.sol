// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {VmSafe} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";
import {SingletonFactory} from "../../src/SingletonFactory.sol";

contract NestedCreate {
    VmSafe internal constant VM = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    ISingletonFactory private immutable FACTORY;
    Context private _ctx;
    uint256 private _constructorCallValue;
    bool private _validated;
    NestedCreate private _child;

    constructor(ISingletonFactory factory) payable {
        FACTORY = factory;
        Context memory ctx = factory.context();
        require(ctx.contractAddress == address(this), "Can only be created by `SingletonFactory`");
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

        if (ctx.hasCallback) {
            require(ctx.callbackSelector == NestedCreate.validateContext.selector, "invalid callback selector");
            require(msg.value == 0, "cannot send value to constructor when using callback");
        }
        require(ctx.data.length >= 32, "invalid ctx.data length");
        _constructorCallValue = msg.value;
        _ctx = ctx;
        _validated = false;
        _child = NestedCreate(payable(_create(address(factory), ctx.data)));
    }

    function _create(address factory, bytes memory data) private returns (address) {
        uint256[] memory depthArray = abi.decode(data, (uint256[]));
        if (depthArray.length > 0) {
            uint256 depth = depthArray[depthArray.length - 1];
            require(depth == _ctx.callDepth, "depth != _ctx.callDepth");

            // Remove the last element from `depthArray`
            assembly {
                mstore(depthArray, sub(mload(depthArray), 1))
            }

            // Copy creation code to memory
            bytes memory creationCode;
            assembly {
                creationCode := mload(0x40)
                mstore(creationCode, codesize())
                codecopy(add(creationCode, 0x20), 0, codesize())
                {
                    let offset := add(creationCode, add(0x20, codesize()))
                    offset := and(add(offset, 0x1f), 0xffffffffffffffe0)
                    mstore(0x40, offset)
                }
            }
            uint256 salt = _ctx.salt + 0x0101010101010101010101010101010101010101010101010101010101010101;
            return ISingletonFactory(factory).create2(salt, creationCode, abi.encode(depthArray));
        }
        return address(0);
    }

    function context() external view returns (Context memory, bool, NestedCreate) {
        require(msg.sender != address(FACTORY), "factory cannot call context");
        return (_ctx, _validated, _child);
    }

    function validateContext() external {
        require(msg.sender == address(FACTORY), "only the SingletonFactory can call this method");
        require(_validated == false, "already validated");
        Context memory ctx = FACTORY.context();
        require(ctx.contractAddress == address(this), "address mismatch");
        require(ctx.sender == _ctx.sender, "sender mismatch");
        require(ctx.salt == _ctx.salt, "salt mismatch");
        require(ctx.callDepth == _ctx.callDepth, "call depth mismatch");
        require(ctx.hasCallback == _ctx.hasCallback, "has callback mismatch");
        require(ctx.callbackSelector == _ctx.callbackSelector, "callback selector mismatch");
        require(keccak256(ctx.data) == keccak256(_ctx.data), "data mismatch");
        _validated = true;
    }
}
