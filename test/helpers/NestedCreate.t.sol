// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Context, IUniversalFactory} from "../../src/IUniversalFactory.sol";

contract NestedCreate {
    IUniversalFactory private FACTORY;
    Context private _ctx;
    uint256 private _constructorCallValue;
    bool private _validated;
    NestedCreate private _child;

    constructor(IUniversalFactory factory) payable {
        FACTORY = factory;
        Context memory ctx = factory.context();
        require(ctx.contractAddress == address(this), "Can only be created by `UniversalFactory`");

        if (ctx.hasCallback) {
            require(ctx.callbackSelector == NestedCreate.validateContext.selector, "invalid callback selector");
            require(msg.value == 0, "cannot send value to constructor when using callback");
        }
        require(ctx.data.length >= 96, "invalid ctx.data length");
        _constructorCallValue = msg.value;
        _ctx = ctx;
        _validated = false;
        _child = NestedCreate(payable(_create(factory, ctx)));
    }

    function _create(IUniversalFactory factory, Context memory ctx) private returns (address) {
        uint256[] memory depthArray = abi.decode(ctx.data, (uint256[]));
        require(depthArray.length > 0, "invalid depthArray");
        uint256 depth = depthArray[depthArray.length - 1];
        require(depth == ctx.callDepth, "depth != _ctx.callDepth");

        // Remove the last element from `depthArray`
        assembly {
            mstore(depthArray, sub(mload(depthArray), 1))
        }

        if (depthArray.length > 0) {
            // Copy creation code to memory
            uint256 codeSize;
            assembly {
                codeSize := codesize()
            }
            bytes memory creationCode = new bytes(codeSize);
            assembly {
                codecopy(add(creationCode, 0x20), 0, codesize())
            }
            bytes32 salt =
                bytes32(uint256(ctx.salt) + 0x0101010101010101010101010101010101010101010101010101010101010101);

            address child;
            if (ctx.hasCallback) {
                child = factory.create2(
                    salt, creationCode, abi.encode(depthArray), abi.encodeCall(NestedCreate.validateContext, ())
                );
            } else {
                child = factory.create2(salt, creationCode, abi.encode(depthArray));
            }
            return child;
        }
        return address(0);
    }

    function context() external view returns (Context memory, bool, NestedCreate) {
        require(msg.sender != address(FACTORY), "factory cannot call context");
        return (_ctx, _validated, _child);
    }

    function validateContext() external {
        require(msg.sender == address(FACTORY), "only the UniversalFactory can call this method");
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
