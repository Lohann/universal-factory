## Universal Factory

**Use Universal Factory to deploy contracts anywhere!**

**Universal Factory** is derived from [EIP-2470](https://eips.ethereum.org/EIPS/eip-2470) and [EIP-3171](https://github.com/ethereum/EIPs/pull/3171), with an additional feature that allows the contract constructor to access arguments without including it in the bytecode, this way custom arguments can be provided and immutables can be set without influencing the final `create2` address.

### 1. Initialize immutables without contructor parameters.

You can initialize  to set immutables without having to set any parameter, once constructor parameters changes the final `create2` address.
In this example, only the account `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef` can create this contract, so as long the contract `creationCode` doesn't change, the final address doesn't change either.
```solidity
import {Context, IUniversalFactory} from "universal-factory/src/UniversalFactory.sol";

contract CrossChainOwned {
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x000000000000e27221183e5c85058c31df6a7d01);
    address internal constant OWNER = IUniversalFactory(0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef);
    uint256 immutable public IMMUTABLE_VALUE;

    constructor() {
        require(msg.sender == address(FACTORY), "can only be created using Universal Factory");
        Context memory ctx = factory.context();

        // Actual sender, who called the UniversalFactory
        require(ctx.sender == address(OWNER), "unauthorized");

        // Can initialize immutable, without influecing the create2 address.
        IMMUTABLE_VALUE = abi.decode(ctx.data, (uint256));
    }
}
```

Usage
```solidity
import {CrossChainOwned} from "./CrossChainOwned.sol";

address owner = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
uint256 salt = 1234;
bytes memory creationCode = type(CrossChainOwned).creationCode;
bytes memory arguments = abi.encode(uint256(1337));
vm.startBroadcast(owner);
CrossChainOwned myContract = CrossChainOwned(factory.create2(salt, creationCode, arguments));
vm.stopBroadcast();
```

### 2. Reserved Addresses
Reserve an address, and use it to deploy an custom bytecode later in ANY network.
```solidity
import {Context, IUniversalFactory} from "universal-factory/src/UniversalFactory.sol";

contract Reserved {
    IUniversalFactory internal constant FACTORY = IUniversalFactory(0x000000000000e27221183e5c85058c31df6a7d01);
    address internal constant OWNER = IUniversalFactory(0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef);

    constructor() payable {
        require(msg.sender == address(FACTORY), "can only be created using Universal Factory");
        Context memory ctx = factory.context();
        require(ctx.sender == address(OWNER), "unauthorized");

        // Create an arbitrary contract at an deterministic address that only the
        // `OWNER` can use.
        bytes memory creationCode = ctx.data;
        address newContract;
        assembly {
            newContract := create(selfbalance(), add(creationCode, 0x20), mload(creationCode))
        }
        require(newContract != address(0), "failed to create contract");
    }
}
```

How to deploy an arbitrary contract at an reserved address:
```solidity
import {Reserved} from "./Reserved.sol";
contract MyContract {
    constructor() { ... }
}

IUniversalFactory factory = IUniversalFactory(0x000000000000e27221183e5c85058c31df6a7d01);
uint256 salt = 1;
bytes memory reservedContract = type(Reserved).creationCode;
bytes memory creationCode = type(MyContract).creationCode;

// The final contract address is only influenced by `salt` and `reservedContract`.
MyContract myContract = MyContract(factory.create2(salt, reservedContract, creationCode));
```

Information available in the **Context**:
-   **contractAddress**: The address of the contract being created, useful if a third contract calls `factory.context()`.
-   **sender**: actual `msg.sender` who called the `UniversalFactory`.
-   **callDepth**: current call depth, used when creating contract in neast.
-   **kind**: type of create method being used, `create2` or `create3`, obs: for create3 `msg.sender != address(FACTORY)`.
-   **hasCallback** Wheter who called provided an callback or not.
-   **callbackSelector** first 4 bytes of the callback payload.
-   **value** If a callback is provided, the `msg.value` is sent to the callback, not the constructor, this field makes the value available in the constructor.
-   **salt** The salt used to derive this address.
-   **data** Additional data with no specified format

## Available Network
The Universal Factory is already available in 12 networks at address `0x000000000000e27221183e5c85058c31df6a7d01`:
-  [**Ethereum Mainnet**](https://etherscan.io/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Ethereum Classic**](https://etc.tokenview.io/en/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Sepolia**](https://sepolia.etherscan.io/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Holesky**](https://holesky.etherscan.io/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Polygon POS**](https://polygonscan.com/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Polygon Amoy**](https://amoy.polygonscan.com/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Arbitrum One**](https://arbiscan.io/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Arbitrum One Sepolia**](https://sepolia.arbiscan.io/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Avalanche C-Chain**](https://subnets.avax.network/c-chain/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**BNB Smart Chain**](https://bscscan.com/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**BNB Smart Chain Testnet**](https://testnet.bscscan.com/address/0x000000000000e27221183e5c85058c31df6a7d01)
-  [**Moonbase**](https://moonbase.moonscan.io/address/0x000000000000e27221183e5c85058c31df6a7d01)

#### Comming soon:
- Moonbean
- Moonriver
- Astar
- Astar zkEVM
- Shibuya
- Shiden
- Polygon zkEVM
- Optimins
- Goerli

_If you are missing some network, please open an issue._

## Pending - Keyless Deployment
Once properly **audited** and **reviewed**, this contract is going to be deployed using the keyless deployment method—also known as Nick’s method—which relies on a single-use address. (See [Nick’s article](https://weka.medium.com/how-to-send-ether-to-11-440-people-187e332566b7) for more details). This method works as follows:

Generate a transaction which deploys the contract from a new random account.
This transaction MUST NOT use EIP-155 in order to work on any chain.
This transaction MUST have a relatively high gas price to be deployed on any chain. In this case, it is going to be 100 Gwei.
Set the v, r, s of the transaction signature to the following values:
```
v: 27,
r: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
s: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
```
Those `r` and `s` values—made of a repeating pattern of `deadbeef`’s—are predictable “random numbers” generated deterministically by a human.

We recover the sender of this transaction, i.e., the single-use deployment account.

Thus we obtain an account that can broadcast that transaction, but we also have the warranty that nobody knows the private key of that account.

Send exactly 1 ether to this single-use deployment account.

Broadcast the deployment transaction.

## Contributing

You can also contribute to this repo in a number of ways, including.

- Asking questions
- Request features (will be analysed)
- Giving feedback
- Reporting bugs or vulnerabilities.

## License

This project is released under [MIT](LICENSE).