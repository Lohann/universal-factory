// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUniversalFactory, Context} from "../../src/IUniversalFactory.sol";

/**
 * @dev Reserved contract, enforces who can deploy it and how
 *      it must be initialized.
 */
contract ReservedContract {
    IUniversalFactory private immutable FACTORY;
    bytes32 public immutable NONCE;

    /**
     * When using `UniversalFactory.create2`, the values provided to
     * the constructor influences the final contract address, while
     * values provided via UniversalFactory.context doesn't.
     *
     * Tip: Using both allows the deployer to choose what values affect
     * the contract address and which ones don't. In this example the
     * arguments `factory` and `owner` affect the address, but `salt` don't.
     */
    constructor(IUniversalFactory factory, address owner) {
        Context memory ctx = factory.context();

        // Only the Universal Factory can create this contract
        require(msg.sender == address(factory), "unauthorized");

        // The msg.sender must the owner of this contract.
        require(ctx.sender == owner, "unauthorized sender");

        // Make sure the this contract is being created, this prevents
        // executing this constructor using delegate call.
        require(ctx.contractAddress == address(this), "address mismatch");

        // Enforces this contract must be initialized by calling a callback method,
        // useful when deploying Proxy contracts.
        require(ctx.hasCallback, "requires callback");

        // Verify the callback selector (first 4 bytes), for Proxy contracts this makes
        // sure the correct iniatilization method will be called.
        require(ctx.callbackSelector == ReservedContract.initialize.selector, "invalid callback");

        // (optional) make sure this is not a nested call to Universal Factory.
        // remove this check to allow the current context to be child of another contract
        // being deployed/initialized by the Universal Factory.
        // Ex: UniversalFactory.create2 -> new Parent() -> UniversalFactory.create2 -> new Child()
        require(ctx.callDepth == 1, "depth mismatch");

        // Store the immutables
        NONCE = ctx.salt;
        FACTORY = factory;
    }

    /**
     * Guaranteed to be the first method executed after the contract deploy.
     *
     * Advantages:
     * 1. Constructor logic makes impossible to deploy this contract without initializing it.
     * 2. The UniversalFactory is guaranteed to call this method only once.
     * 3. When it enforces only the UniversalFactory can execute it, there's no need to
     *    persist a `initialized` state, because is impossible to execute it twice.
     *
     * Use cases
     * 1. Proxy Contracts, which cannot be initialized in the constructor.
     * 2. Calling another constract during inialization which calls a method
     *    of this contract, ex `ERC721Receiver` interface to move NFTs.
     */
    function initialize() external payable {
        require(msg.sender == address(FACTORY), "unauthorized");
        require(msg.value > 0, "must send funds");
    }
}
