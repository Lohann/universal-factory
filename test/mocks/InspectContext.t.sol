// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Context, IUniversalFactory} from "../../src/UniversalFactory.sol";

contract InspectContext {
    IUniversalFactory private immutable FACTORY;
    Context private _ctx;
    uint256 private _constructorCallValue;
    bool private _initialized;
    bytes private _callback;

    constructor(IUniversalFactory factory) payable {
        FACTORY = factory;
        Context memory ctx = factory.context();
        if (ctx.hasCallback) {
            require(msg.value == 0, "cannot send value to constructor when using callback");
        }
        _constructorCallValue = msg.value;
        _ctx = ctx;
        _initialized = false;
        _callback = new bytes(0);
    }

    function context() external view returns (Context memory, bool, bytes memory) {
        require(msg.sender != address(FACTORY), "factory cannot call context");
        require(_initialized == _ctx.hasCallback, "not initialized");
        return (_ctx, _initialized, _callback);
    }

    fallback() external payable {
        require(msg.sender == address(FACTORY), "only factory can call fallback");
        require(_initialized == false, "already initialized");
        require(_ctx.hasCallback, "no callback expected");
        _initialized = true;
        _callback = msg.data;
    }

    receive() external payable {
        require(msg.sender == address(FACTORY), "only factory can call fallback");
        require(_initialized == false, "already initialized");
        require(_ctx.hasCallback, "no callback expected");
        _initialized = true;
    }
}
