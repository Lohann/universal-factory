# Universal Factory

**Use Universal Factory to choose the address of your contracts anywhere!**

**Universal Factory** is inspired by [EIP-2470 Singleton Factory](https://eips.ethereum.org/EIPS/eip-2470) and [EIP-3171 CREATE3 OPCODE](https://github.com/ethereum/EIPs/pull/3171), with an additional feature that allows the contract constructor to access arguments without including it in the bytecode, this way custom arguments can be provided and immutables can be set without influencing the final `CREATE2` address.

## How it works?
When creating a contract, **Universal Factory** caches the provided `arguments`, `salt`, `msg.sender`, and other relevant info locally. Then make it available to the contract constructor through the `context()` method. The caching mechanism depends on the EVM version:
- For `cancun` it uses the `TLOAD` and `TSTORE` opcodes from [EIP-1153 Transient Storage](https://eips.ethereum.org/EIPS/eip-1153) (~100 gas per word).
- For `shanghai` it uses the `SLOAD` and `SSTORE` opcodes (~2900 gas per word), plus it make sure all values stored are non-zero, to guarantee an low and constant gas cost (see [SSTORE gas calculation](https://github.com/wolflo/evm-opcodes/blob/main/gas.md#a7-sstore) for more details).
    - Context data storage slots are [initialized with non-zero](./src/UniversalFactory.sol#L286-L290) values in the Universal Factory constructor.
    - `msg.value` is only stored when [greater than zero](./src/UniversalFactory.sol#L872).
    - `salt` is [XOR with context data](./src/UniversalFactory.sol#L864-L869) being stored/loaded.
    - `arguments` are [XOR with keccak256(arguments)](src/UniversalFactory.sol#L874-L888) before being stored/loaded.
    - Obs: `arguments` slots aren't initialized with non-zero, but once initialized, is impossible to set it back to zero again.
- The contract [automatically detects the EVM version](./src/UniversalFactory.sol#L536-L540), and will use EIP-1153 if available.

## Features

For examples on how to use the Universal Factor, see the [test/examples](./test/examples/) folder.

## CREATE2 Methods
```solidity
function create2(bytes32 salt, bytes calldata creationCode) external payable returns (address);

function create2(bytes32 salt, bytes calldata creationCode, bytes calldata arguments)
    external
    payable
    returns (address);

function create2(bytes32 salt, bytes calldata creationCode, bytes calldata arguments, bytes calldata callback)
    external
    payable
    returns (address);
```
- `salt` the salt of the contract creation, this value affect the resulting address.
- `creationCode` Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
- `arguments` data that will be available at `Context.data`, this field doesn't affect the resulting address.
- `callback` callback called after create the contract, this field doesn't affect the resulting address.
    - Obs: when using `create2(bytes32,bytes,bytes,bytes)` method, the callback is always called, even if the callback is empty.

The address of a contracts deployed with `CREATE2` can be deterministically computed as:
```solidity
function computeCreate2Address(bytes32 salt, bytes memory creationCode) external pure returns (address contractAddress) {
    bytes32 creationCodeHash = keccak256(creationCode);
    bytes32 create2hash = keccak256(abi.encodePacked(
        hex"ff0000000000001c4bf962df86e38f0c10c7972c6e",
        salt,
        creationCodeHash
    ));
    contractAddress = address(uint160(uint256(create2hash)));
}
```

## CREATE3 vs CREATE2
```solidity
function create3(bytes32 salt, bytes calldata creationCode) external payable returns (address);

function create3(bytes32 salt, bytes calldata creationCode, bytes calldata arguments)
    external
    payable
    returns (address);

function create3(bytes32 salt, bytes calldata creationCode, bytes calldata arguments, bytes calldata callback)
    external
    payable
    returns (address);
```
Works the same way as [CREATE2](./README.md#create2-methods), except the resulting address is derived differently:
 - `creationCode` doesn't influence the resulting address.
 - `msg.sender` or deployer address influence the resulting address.

The address of a contracts deployed with `CREATE3` can be deterministically computed as:
```solidity
function computeCreate3Address(address deployer, bytes32 salt) external pure returns (address contractAddress) {
    bytes32 create3salt = keccak256(abi.encodePacked(deployer, salt));
    bytes32 create2hash = keccak256(abi.encodePacked(
        hex"ff0000000000001c4bf962df86e38f0c10c7972c6e",
        create3salt,
        hex"0281a97663cf81306691f0800b13a91c4d335e1d772539f127389adae654ffc6"
    ));
    address create3proxy = address(uint160(uint256(create2hash)));
    bytes32 create3hash = keccak256(abi.encodePacked(hex"d694", create3proxy, uint8(0x01)));
    contractAddress = address(uint160(uint256(create3hash)));
}
```

## Deployments [Universal Factory](./src/UniversalFactory.sol)
The Universal Factory is already available in 8 blockchains and 7 testnets at address `0x0000000000001C4Bf962dF86e38F0c10c7972C6E`:

-  [**Ethereum Mainnet**](https://etherscan.io/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
   - [0x3a35fa7f599f89dd89abfd527cad924f8e4dcc08b82408ebbd0c34eb70479449](https://etherscan.io/tx/0x3a35fa7f599f89dd89abfd527cad924f8e4dcc08b82408ebbd0c34eb70479449)
-  [**Ethereum Classic**](https://etc.tokenview.io/en/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
   - [0x290fb160b777160e8c4e183ff54eb0347fab28ef4388e0f3f11a064697e478ae](https://etc.tokenview.io/en/tx/0x290fb160b777160e8c4e183ff54eb0347fab28ef4388e0f3f11a064697e478ae)
-  [**Sepolia**](https://sepolia.etherscan.io/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
   - [0x0442e9f14fc14d868c3e5cb5d24e71fa237c41f0f6380bee66865212321f2217](https://sepolia.etherscan.io/tx/0x0442e9f14fc14d868c3e5cb5d24e71fa237c41f0f6380bee66865212321f2217)
-  [**Holesky**](https://holesky.etherscan.io/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0xf49269f2a68b5e2563d21765e75698b5cd6b46291e546ac8d1313068c6437a60](https://holesky.etherscan.io/tx/0xf49269f2a68b5e2563d21765e75698b5cd6b46291e546ac8d1313068c6437a60)
-  [**Polygon PoS**](https://polygonscan.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
    - [0x6778204b5feae624ae1aa818696f290a9f37ddedde8a93b0f84f7ba3f6f348c9](https://polygonscan.com/tx/0x6778204b5feae624ae1aa818696f290a9f37ddedde8a93b0f84f7ba3f6f348c9)
-  [**Polygon Amoy**](https://amoy.polygonscan.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0x545d4bb1d62ed46c373ac7f31de9558db339e6a579dab621888ae6e9012676b4](https://amoy.polygonscan.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
-  [**Arbitrum One**](https://arbiscan.io/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
    - [0xa97cbd5cc2e1747f3bff06006a80facdfadb2a43862c3260ebce2dc4186bca4e](https://arbiscan.io/tx/0xa97cbd5cc2e1747f3bff06006a80facdfadb2a43862c3260ebce2dc4186bca4e)
-  [**Arbitrum One Sepolia**](https://sepolia.arbiscan.io/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0x1630e2bc331c93f0026c67ee4a6ac059c27b7dee5c885c4fed68fbe0edd8b192](https://sepolia.arbiscan.io/tx/0x1630e2bc331c93f0026c67ee4a6ac059c27b7dee5c885c4fed68fbe0edd8b192)
-  [**Avalanche C-Chain**](https://subnets.avax.network/c-chain/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E):
    - [0x3f98542641cc5bb06a4b976a9df0bc847efde967d44d72e3b175a8877c737753](https://subnets.avax.network/c-chain/tx/0x3f98542641cc5bb06a4b976a9df0bc847efde967d44d72e3b175a8877c737753)
-  [**Avalanche Fuji**](https://testnet.avascan.info/blockchain/c/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0x1ade68ab1356f7dd45ee4b23330bfda43b33384327c6387377d59347b266bef1](https://testnet.avascan.info/blockchain/c/tx/0x1ade68ab1356f7dd45ee4b23330bfda43b33384327c6387377d59347b266bef1)
-  [**BNB Smart Chain**](https://bscscan.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
    - [0x614f0b8121aeb123b95b82fc68ed7b053f58540f717335e7a49c1995ac3628da](https://bscscan.com/tx/0x614f0b8121aeb123b95b82fc68ed7b053f58540f717335e7a49c1995ac3628da)
-  [**BNB Smart Chain Testnet**](https://testnet.bscscan.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0xe3bbceaed3e47f5c29c013a6dc7f58e169b8744764b61cf98157ad5a5e1663ab](https://testnet.bscscan.com/tx/0xe3bbceaed3e47f5c29c013a6dc7f58e169b8744764b61cf98157ad5a5e1663ab)
-  [**Moonbase**](https://moonbase.moonscan.io/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0x9aef1d890ecc18bd61b9752c8b61b08129cc270c3dc35358135db967e5d17faf](https://moonbase.moonscan.io/tx/0x9aef1d890ecc18bd61b9752c8b61b08129cc270c3dc35358135db967e5d17faf)
-  [**Astar**](https://astar.blockscout.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E)
    - [0x830be5f66943c287806b7bfd93b448f90c8847d713302cb612245a1c2148a10d](https://astar.blockscout.com/tx/0x830be5f66943c287806b7bfd93b448f90c8847d713302cb612245a1c2148a10d)
-  [**Shibuya**](https://shibuya.blockscout.com/address/0x0000000000001C4Bf962dF86e38F0c10c7972C6E) - testnet
    - [0x33c8357bb029cd3aae6704d368c9d9ec9a7812f5d84bf42690493159895960ce](https://shibuya.blockscout.com/tx/0x33c8357bb029cd3aae6704d368c9d9ec9a7812f5d84bf42690493159895960ce)

#### Comming soon:
- Polygon zkEVM
- Gnosis
- Optimism
- Moonbean
- Moonriver
- Astar zkEVM
- Shiden

_If you are missing some network, please open an issue._

## Keyless Deployment (TODO)
Once properly **audited** and **reviewed**, this contract is going to be deployed using the keyless deployment method—also known as Nick’s method—which relies on a single-use address. (See [Nick’s article](https://weka.medium.com/how-to-send-ether-to-11-440-people-187e332566b7) for more details).

This method works as follows:

1. Generate a transaction which deploys the contract from a new random account.
   - This transaction MUST NOT use EIP-155 in order to work on any chain.
   - This transaction MUST have a relatively high gas price to be deployed on any chain. In this case, it is going to be `200 Gwei`.

2. Set the v, r, s of the transaction signature to the following values:
```
v: 27,
r: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
s: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
```
Those `r` and `s` values—made of a repeating pattern of `deadbeef`’s—are predictable “random numbers” generated deterministically by a human.

3. We recover the sender of this transaction, i.e., the single-use deployment account.

> Thus we obtain an account that can broadcast that transaction, but we also have the warranty that nobody knows the private key of that account.

4. Send exactly `1 ether` to this single-use deployment account.

5. Broadcast the deployment transaction.

## Contributing

You can also contribute to this repo in a number of ways, including.

- Asking questions
- Request features (will be analysed)
- Giving feedback
- Reporting bugs or vulnerabilities.

## License

This project is released under [MIT](LICENSE).