// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUniversalFactory, Context} from "../../src/IUniversalFactory.sol";

/**
 * @dev Reserved contract, can only be deployed by `owner`.
 */
contract ReservedContract {
    IUniversalFactory private immutable FACTORY;
    bytes32 public immutable NONCE;

    constructor(IUniversalFactory factory, address owner) {
        Context memory ctx = factory.context();
        require(msg.sender == address(factory), "unauthorized");
        require(ctx.sender == owner, "unauthorized sender");
        require(ctx.callDepth == 1, "depth mismatch");
        require(ctx.contractAddress == address(this), "address mismatch");
        require(ctx.hasCallback, "requires callback");
        require(ctx.callbackSelector == ReservedContract.initialize.selector, "invalid callback");
        NONCE = ctx.salt;
        FACTORY = factory;
    }

    function initialize() external payable {
        require(msg.sender == address(FACTORY), "unauthorized");
        require(msg.value > 0, "must send funds");
    }
}
