// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";

contract MockContract {
    ISingletonFactory private immutable FACTORY;
    uint256 public immutable NONCE;

    constructor(ISingletonFactory factory, address owner) {
        Context memory ctx = factory.context();
        require(ctx.contractAddress == address(this), "address mismatch");
        require(ctx.callDepth == 1, "depth mismatch");
        require(ctx.sender == owner, "unauthorized tx origin");
        require(ctx.hasCallback, "requires callback");
        require(ctx.callbackSelector == MockContract.initialize.selector, "invalid callback");
        NONCE = ctx.salt;
        FACTORY = factory;
    }

    function initialize() external payable {
        require(msg.sender == address(FACTORY), "unauthorized");
        require(msg.value > 0, "send money!!");
    }
}
