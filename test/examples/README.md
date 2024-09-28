## Examples

### 1. Initialize immutables without constructor parameters.

You can initialize  to set immutables without having to set any parameter, once constructor parameters changes the final `create2` address.
In this example, only the contract owner can create this contract, so as long the `owner`, `creationCode` and `salt` doesn't change, the final address doesn't change either.
```solidity
contract Example01 {
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x0000000000001C4Bf962dF86e38F0c10c7972C6E);
    address internal constant OWNER = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;
    uint256 private immutable IMMUTABLE_A;
    bytes32 private immutable IMMUTABLE_B;

    // Any value defined in the constructor influences the CREATE2 address.
    constructor() {
        Context memory ctx = FACTORY.context();
        require(ctx.contractAddress == address(this));

        // Only the `OWNER` can create this contract.
        require(ctx.sender == OWNER, "unauthorized");

        // Can initialize immutables, without influecing the create2 address.
        (IMMUTABLE_A, IMMUTABLE_B) = abi.decode(ctx.data, (uint256, bytes32));
    }
}
```

- file: [Owner.sol](./Owner.sol)
- test: [Owner.t.sol](./Owner.t.sol)

### 2. Callbacks and Custom owned addresses
Is possible to define custom rules for deploying cross-chain contracts, create custom `CREATE3` rules, etc...

- file: [Deployer.sol](./Deployer.sol), [MyContract.sol](./MyContract.sol)
- test: [Deployer.t.sol](./Deployer.t.sol)

Example: Using `ecrecover` allow anyone besides the owner to deploy a contract, as long the owner has provided the signature,
and a boolean saying if this signature is valid for all blockchain, or just for this particular eip155 chain-id.
```solidity
contract Example02 {
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x0000000000001C4Bf962dF86e38F0c10c7972C6E);
    address public immutable OWNER;

    // Obs: the `owner` parameter affects the resulting address, which is desired in this case to
    // bound the contract address to a specific owner.
    constructor(address owner) payable {
        // set the immutable.
        OWNER = owner;

        // Make sure the `Deployer` is created using the `Universal Factory`.
        Context memory ctx = FACTORY.context();
        require(ctx.contractAddress == address(this));
        require(ctx.kind == CreateKind.CREATE2, "must use CREATE2");

        // Compute the digest and check if the `owner` has authorized this contract deployment or not.
        (uint8 v, bytes32 r, bytes32 s, bool isUniversal) = abi.decode(ctx.data, (uint8, bytes32, bytes32, bool));
        bytes32 digest;
        if (isUniversal) {
            // This contract can be deployed in any blockchain.
            digest = keccak256(abi.encode(address(this)));
        } else {
            // This contract can only deployed in this specific chain.
            digest = keccak256(abi.encode(address(this), block.chainid));
        }

        // Check the signature
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "unauthorized");
    }
}
```
