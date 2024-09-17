// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

// import {VmSafe} from "forge-std/Vm.sol";
// import {Test, console} from "forge-std/Test.sol";
import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";
import {SingletonFactory} from "../../src/SingletonFactory.sol";

contract NestedCreate {
    ISingletonFactory private immutable FACTORY;
    Context private _ctx;
    uint256 private _constructorCallValue;
    bool private _initialized;
    NestedCreate private _child;

    constructor(ISingletonFactory factory) payable {
        FACTORY = factory;
        Context memory ctx = factory.context();
        if (ctx.hasCallback) {
            require(msg.value == 0, "cannot send value to constructor when using callback");
        }
        require(ctx.data.length == 0 || ctx.data.length > 4, "invalid ctx.data length");
        _constructorCallValue = msg.value;
        _ctx = ctx;
        _initialized = false;
        if (!ctx.hasCallback && ctx.data.length > 0) {
            _child = NestedCreate(payable(_create(address(factory), ctx.data)));
        }
    }

    function _create(address factory, bytes memory data) private returns (address) {
        (uint8 callDepth, bytes memory callData) = abi.decode(data, (uint8, bytes));
        require(callDepth == _ctx.callDepth, "callDepth != _ctx.callDepth");
        (bool success, bytes memory result) = factory.call(callData);
        if (!success) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
        return abi.decode(result, (address));
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
