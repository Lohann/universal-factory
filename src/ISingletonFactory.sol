// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

enum CreateKind {
    CREATE2,
    CREATE3
}

struct Context {
    address contractAddress;
    address sender;
    uint8 callDepth;
    CreateKind kind;
    bool hasCallback;
    bytes4 callbackSelector;
    uint256 value;
    uint256 salt;
    bytes data;
}

interface ISingletonFactory {
    /**
     * @dev The `initCode` reverted, it was executed by `SingletonFactory` using `CREATE2` OPCODE.
     */
    error Create2Failed();

    /**
     * @dev The `initCode` reverted, it was executed by the `ChildProxy` using `CREATE` OPCODE.
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
     * Creates an contract at a deterministic address, the final address is derived from the
     * `salt` and `creationCode`, and is computed as follow:
     * ```solidity
     * return address(uint160(uint256(keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), keccak256(creationCode))))));
     * ```
     * The contract constructor can access the actual sender and other information by calling `context()`.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
     */
    function create2(uint256 salt, bytes calldata creationCode) external payable returns (address);

    /**
     * Same as above, except it also accept a callback to call the contract after it is created, useful for initialize proxies for example.
     * The contract contructor can enforce it is initialized by retrieving the `Context` and checking the `hasInitializer`,
     * `initializerSlice` and `initializerLength` fields.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
     * @param data data that will be available for the contract at `Context.data`, this field doesn't affect the resulting address.
     */
    function create2(uint256 salt, bytes calldata creationCode, bytes calldata data)
        external
        payable
        returns (address);

    /**
     * Same as above, except it also accept a callback to call the contract after it is created, useful for initialize proxies for example.
     * The contract contructor can enforce it is initialized by retrieving the `Context` and checking the `hasInitializer`,
     * `initializerSlice` and `initializerLength` fields.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value affect the resulting address.
     * @param data data that will be available for the contract at `Context.data`, this field doesn't affect the resulting address.
     * @param callback callback called after create the contract, this field doesn't affect the resulting address.
     */
    function create2(uint256 salt, bytes calldata creationCode, bytes calldata data, bytes calldata callback)
        external
        payable
        returns (address);

    /**
     * Creates an contract at a deterministic address, the final address is derived exclusively from the `salt` field:
     * ```solidity
     * bytes32 proxyHash = 0x9fc904680de2feb47c597aa19f58746c0a400d529ba7cfbe3cda504f5aa7914b;
     * address proxy = address(uint160(uint256(keccak256(abi.encodePacked(uint8(0xff), address(factory), uint256(salt), proxyHash)))));
     * return address(uint160(uint256(keccak256(abi.encodePacked(uint16(0xd694), proxy, uint8(1))))));
     * ```
     * The contract constructor can access the actual sender and other informations by calling `context()`.
     *
     * @param salt Salt of the contract creation, resulting address will be derivated from this value only.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address.
     */
    function create3(uint256 salt, bytes calldata creationCode) external payable returns (address);

    /**
     * Same as above, except it also accept a callback to call the contract after it is created, useful for initialize proxies for example.
     * The contract contructor can enforce it is initialized by retrieving the `Context` and checking the `hasInitializer`,
     * `initializerSlice` and `initializerLength` fields.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address.
     * @param data data that will be available for the contract at `Context.data`, this value doesn't affect the resulting address.
     */
    function create3(uint256 salt, bytes calldata creationCode, bytes calldata data)
        external
        payable
        returns (address);

    /**
     * Same as above, except it also accept a callback to call the contract after it is created, useful for initialize proxies for example.
     * The contract contructor can enforce it is initialized by retrieving the `Context` and checking the `hasInitializer`,
     * `initializerSlice` and `initializerLength` fields.
     *
     * @param salt Salt of the contract creation, this value affect the resulting address.
     * @param creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address.
     * @param data data that will be available for the contract at `Context.data`, this value doesn't affect the resulting address.
     * @param callback callback called after create the contract, this field doesn't affect the resulting address.
     */
    function create3(uint256 salt, bytes calldata creationCode, bytes calldata data, bytes calldata callback)
        external
        payable
        returns (address);

    /**
     * @dev returns the current call context, returns zero for all fields if there's no context.
     * This function provides useful information that can be accessed inside the contract constructor.
     * Examples:
     * The `Context.data` to set immutables in the contract without affect the final address.
     * The `Context.sender` to enforce the contract can only be created by a specific address, etc.
     * The `Context.callbackSelector` to enforce a specific function will be called after creation.
     */
    function context() external view returns (Context memory);
}
