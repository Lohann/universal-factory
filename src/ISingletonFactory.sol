// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

struct Context {
    address contractAddress;
    address sender;
    uint256 salt;
    uint8 callDepth;
    bool hasInitializer;
    bytes initializer;
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
     * @dev The final `address(this).balance` of the `SingletonFactory` is greater than zero.
     */
    error InvalidSelfBalance(uint256);

    /**
     * @dev The `initializer` reverted, this error wraps the revert reason returned by contract.
     */
    error InitializerReverted(bytes);

    /**
     * @dev The deterministic address was used already.
     */
    error ContractAlreadyExists(address);

    /**
     * @dev The provided `initCode` is reserved for internal use only, try to use `create3` instead.
     */
    error ReservedInitCode();

    /**
     * @dev The previous context is invalid.
     * This only happens when calling this contract using `delegatecall`, probably because this
     * contract expects the slots 0, 1 and 2 to be set to `type(uint256).max`, once they are used
     * as transient storage for the call context.
     */
    error PreviousContextInvalid(address, address, uint256, uint8, bool, uint32, bytes19);

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
     * @param params callback called after create the contract, this field doesn't affect the resulting address.
     */
    function create2(uint256 salt, bytes calldata creationCode, bytes calldata params)
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
     * @param params callback called after create the contract, this value doesn't affect the resulting address.
     */
    function create3(uint256 salt, bytes calldata creationCode, bytes calldata params)
        external
        payable
        returns (address);

    /**
     * @dev returns the current call context, returns zero for all fields if there's no context.
     */
    function context() external view returns (Context memory);
}
