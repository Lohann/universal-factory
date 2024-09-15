// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

// import {VmSafe} from "forge-std/Vm.sol";
// import {Test, console} from "forge-std/Test.sol";
import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";
import {SingletonFactory} from "../../src/SingletonFactory.sol";

contract InspectContext {
    ISingletonFactory private immutable FACTORY;
    Context private _ctx;
    uint256 private _constructorCallValue;
    bool private _initialized;
    bytes private _initializer;

    constructor(ISingletonFactory factory) payable {
        FACTORY = factory;
        Context memory ctx = factory.context();
        if (ctx.hasInitializer) {
            require(msg.value == 0, "cannot send value with initializer");
        }
        _constructorCallValue = msg.value;
        _ctx = ctx;
        _initialized = false;
        _initializer = new bytes(0);
    }

    function context() external view returns (Context memory, bool, bytes memory) {
        require(msg.sender != address(FACTORY), "factory cannot call context");
        require(_initialized == _ctx.hasInitializer, "not initialized");
        return (_ctx, _initialized, _initializer);
    }

    fallback() external payable {
        require(msg.sender == address(FACTORY), "only factory can call fallback");
        require(_initialized == false, "already initialized");
        require(_ctx.hasInitializer, "no initialization expected");
        _initialized = true;
        _initializer = msg.data;
    }

    receive() external payable {
        require(msg.sender == address(FACTORY), "only factory can call fallback");
        require(_initialized == false, "already initialized");
        require(_ctx.hasInitializer, "no initialization expected");
        _initialized = true;
    }
}
