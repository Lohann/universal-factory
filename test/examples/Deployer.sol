// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Context, IUniversalFactory} from "@universal-factory/UniversalFactory.sol";

// The `Deployer` contract is responsible for deploying the `MyContract` contract.
// The `arguments` contains owner's signature authorizing the deployment of a specific creationCodeHash by anyone.
contract Deployer {
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x0000000000001C4Bf962dF86e38F0c10c7972C6E);
    address public immutable OWNER;
    bytes32 public immutable CODE_HASH;

    constructor(address owner) payable {
        Context memory ctx = FACTORY.context();
        // Make sure the `Deployer` is created by the `FACTORY`.
        require(ctx.contractAddress == address(this));

        // Compute the digest and check if the `owner` has authorized this deployment or not.
        (uint8 v, bytes32 r, bytes32 s, bytes32 creationCodeHash) =
            abi.decode(ctx.data, (uint8, bytes32, bytes32, bytes32));
        bytes32 digest = keccak256(abi.encodePacked(address(this), creationCodeHash, block.chainid));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "unauthorized");

        // Set the immutables.
        OWNER = owner;
        CODE_HASH = creationCodeHash;

        // If a callback is provided, the method `deploy` must be called.
        if (ctx.hasCallback) {
            require(ctx.callbackSelector == Deployer.deploy.selector, "invalid callback");
        }
    }

    // Only an authorized `creationCode` can be deployed in this address.
    function deploy(bytes memory creationCode) external payable returns (address addr) {
        // Check if the provided `creationCode` is authorized one.
        bytes32 creationCodeHash = keccak256(creationCode);
        require(creationCodeHash == CODE_HASH, "unauthorized creation code");

        // Deploy the contract.
        assembly {
            addr := create(selfbalance(), add(creationCode, 0x20), mload(creationCode))
        }
        require(addr != address(0), "failed to create contract");
    }
}
