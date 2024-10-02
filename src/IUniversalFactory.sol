// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @dev The type of create operation being used by the current context.
 */
enum CreateKind {
    CREATE2,
    CREATE3
}

/**
 * @dev Contract Creation Context, this struct is used to provide useful information
 * to the contract constructor, such as the sender, value, call depth, etc. Without affecting
 * the final address of the contract.
 */
struct Context {
    address contractAddress;
    address sender;
    uint8 callDepth;
    CreateKind kind;
    bool hasCallback;
    bytes4 callbackSelector;
    uint256 value;
    bytes32 salt;
    bytes data;
}

/**
 * @dev The interface exposed by the Universal Factory Contract.
 */
interface IUniversalFactory {
    /**
     * @dev The create2 `creationCode` reverted.
     */
    error Create2Failed();

    /**
     * @dev The create3 `creationCode` reverted.
     * obs: Called by `Create3Proxy` using `CREATE` OPCODE.
     */
    error Create3Failed();

    /**
     * @dev The `callback` reverted, this error wraps the revert reason returned by the callback.
     */
    error CallbackFailed(bytes);

    /**
     * @dev The deterministic address already exists.
     */
    error ContractAlreadyExists(address);

    /**
     * @dev The provided `initCode` is reserved for internal use only, try to use `create3` instead.
     */
    error ReservedInitCode();

    /**
     * @dev Maximum call stack of 127 exceeded.
     * OBS: probably impossible to reach this limit, due EIP-150 `all but one 64th`.
     */
    error CallStackOverflow();

    /**
     * @dev Emitted when a contract is succesfully created, this is the only event emitted by the
     * universal factory.
     */
    event ContractCreated(
        address indexed contractAddress,
        bytes32 indexed creationCodeHash,
        bytes32 indexed salt,
        address indexed sender,
        bytes32 argumentsHash,
        bytes32 codeHash,
        bytes32 callbackHash,
        uint8 depth,
        uint256 value
    ) anonymous;

    /**
     * @dev Creates an contract at a deterministic address, the final address is derived from the
     * `salt` and `creationCode`, and is computed as follow:
     * ```solidity
     * return address(uint160(uint256(keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), keccak256(creationCode))))));
     * ```
     * The contract constructor can access the actual sender and other information by calling `context()`.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
     * @return address of the created contract.
     */
    function create2(bytes32 salt, bytes calldata creationCode) external payable returns (address);

    /**
     * @dev Same as `create2(uint256,bytes)`, but also includes `arguments` which will be available at `context.data`.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
     * @param arguments data that will be available at `Context.data`, this field doesn't affect the resulting address.
     * @return address of the created contract.
     */
    function create2(bytes32 salt, bytes calldata creationCode, bytes calldata arguments)
        external
        payable
        returns (address);

    /**
     * @dev Same as `create2(uint256,bytes,bytes)`, but also includes a callback used to call the contract after it is created.
     * @notice The `context.hasCallback` is always set to `true`, this method ALWAYS calls the callback, even if it is empty.
     * IMPORTANT 1: Throws an `CallbackFailed` error if the callback reverts.
     * IMPORTANT 2: Funds sent to this method will be forwarded to the `callback`, not the contract constructor.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
     * @param arguments data that will be available at `Context.data`, this field doesn't affect the resulting address.
     * @param callback callback called after create the contract, this field doesn't affect the resulting address.
     * @return address of the created contract.
     */
    function create2(bytes32 salt, bytes calldata creationCode, bytes calldata arguments, bytes calldata callback)
        external
        payable
        returns (address);

    /**
     * Creates an contract at a deterministic address, the final address is derived exclusively from the `salt` field:
     * ```solidity
     * salt = keccak256(abi.encodePacked(msg.sender, salt));
     * bytes32 proxyHash = 0x0281a97663cf81306691f0800b13a91c4d335e1d772539f127389adae654ffc6;
     * address proxy = address(uint160(uint256(keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), proxyHash)))));
     * return address(uint160(uint256(keccak256(abi.encodePacked(uint16(0xd694), proxy, uint8(1))))));
     * ```
     * The contract constructor can access the actual sender and other informations by calling `context()`.
     *
     * @param salt Salt of the contract creation, resulting address will be derivated from this value only.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address.
     * @return address of the created contract.
     */
    function create3(bytes32 salt, bytes calldata creationCode) external payable returns (address);

    /**
     * @dev Same as `create3(uint256,bytes)`, but also includes `arguments` which will be available at `context.data`.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address.
     * @param arguments data that will be available at `Context.data`, this field doesn't affect the resulting address.
     * @return address of the created contract.
     */
    function create3(bytes32 salt, bytes calldata creationCode, bytes calldata arguments)
        external
        payable
        returns (address);

    /**
     * @dev Same as `create3(uint256,bytes,bytes)`, but also includes a callback used to call the contract after it is created.
     * @notice The `context.hasCallback` is always set to `true`, this method ALWAYS calls the callback, even if it is empty.
     * IMPORTANT 1: Throws an `CallbackFailed` error if the callback reverts.
     * IMPORTANT 2: Funds sent to this method will be forwarded to the `callback`, not the contract constructor.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address.
     * @param arguments data that will be available at `Context.data`, this field doesn't affect the resulting address.
     * @param callback callback called after create the contract, this field doesn't affect the resulting address.
     * @return address of the created contract.
     */
    function create3(bytes32 salt, bytes calldata creationCode, bytes calldata arguments, bytes calldata callback)
        external
        payable
        returns (address);

    /**
     * @dev Current call context, returns zero for all fields if there's no context.
     * This function provides useful information that can be accessed inside the contract constructor.
     * Examples:
     * - `Context.contractAddress` the address of the contract being created.
     * - `Context.sender` actual `msg.sender` who called the UniversalFactory.
     * - `Context.data` to send arguments to the contract constructor without change the resulting address.
     * - `Context.hasCallback` whether a callback was provided or not.
     * - `Context.callbackSelector` first 4 bytes of the callback calldata (zero if no callback is provided).
     * - `Context.callDepth` current call depth, incremented when nested contracts are created.
     * - `Context.salt` the salt used to derive this contract address.
     * - `Context.kind` whether `CREATE2` or `CREATE3` is used.
     * - `Context.value` the value provided, this minimal value between `msg.value` and `address(this).balance` due EVM compatibility.
     * @return Context current call text, or zero for all values if there's no context.
     */
    function context() external view returns (Context memory);
}
