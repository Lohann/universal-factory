/*
 * Universal Factory Contract
 * This standard defines an universal factory smart contract where any address (contract or regular account) can
 * deploy and reserve deterministic contract addresses in any network.
 *
 * Written in 2024 by Lohann Paterno Coutinho Ferreira.
 *
 * SingletonFactory is derived from EIP-2470 and EIP-3171, plus some additional features that allows
 * the creator to reserve an address for future use in any network, given this contract is deployed
 * at the same address on all networks, using keyless deployment methods such as Nick's method:
 * - https://weka.medium.com/how-to-send-ether-to-11-440-people-187e332566b7
 *
 * The goal of this contract is to provide an ultimate solution for deploying contracts at deterministic
 * addresses in any network, the deployer has granular control on what parameters influences the contract address.
 * This allow you to reserve a range of addresses for future use in ANY network, following the rules defined in
 * the contract constructor.
 *
 * References:
 * - EIP-2470: https://eips.ethereum.org/EIPS/eip-2470
 * - EIP-3171: https://github.com/ethereum/EIPs/pull/3171
 * - Keyless Deployment Method: https://weka.medium.com/how-to-send-ether-to-11-440-people-187e332566b7
 *
 *  ██╗   ██╗███╗   ██╗██╗██╗   ██╗███████╗██████╗ ███████╗ █████╗ ██╗
 *  ██║   ██║████╗  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██║
 *  ██║   ██║██╔██╗ ██║██║██║   ██║█████╗  ██████╔╝███████╗███████║██║
 *  ██║   ██║██║╚██╗██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║██║
 *  ╚██████╔╝██║ ╚████║██║ ╚████╔╝ ███████╗██║  ██║███████║██║  ██║███████╗
 *  ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
 *      ███████╗ █████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗
 *      ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
 *      █████╗  ███████║██║        ██║   ██║   ██║██████╔╝ ╚████╔╝
 *      ██╔══╝  ██╔══██║██║        ██║   ██║   ██║██╔══██╗  ╚██╔╝
 *      ██║     ██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║   ██║
 *      ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝
 *
 */
pragma solidity ^0.8.27;

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
    uint256 salt;
    bytes data;
}

/**
 * @dev The interface exposed by the Universal Factory Contract.
 */
interface IUniversalFactory {
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
     * @dev Emitted when a contract is created, anonymous once this is the only event emitted by the
     * universal factory, so more fields can be indexed.
     */
    event ContractCreated(
        address indexed contractAddress,
        bytes32 indexed creationCodeHash,
        uint256 indexed salt,
        bytes32 indexed dataHash,
        bytes32 codeHash,
        bytes32 callbackHash,
        uint8 depth,
        uint256 value
    ) anonymous;

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
     * bytes32 proxyHash = 0xda812570be8257354a14ed469885e4d206be920835861010301b25f5c180427a;
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

/**
 * @title Universal Factory Contract
 * @author Lohann Paterno Coutinho Ferreira
 * @notice This contract is a factory that allows you to deploy contracts at deterministic addresses in any network.
 */
contract UniversalFactory {
    /**
     * @notice The Constructor is payable due Frontier EVM compatibility, once that EVM have the concept
     * of existential deposit (ED), in this evm if you send a balance to a contract without ED, then
     * `address(this).balance < msg.value`, which is impossible in most EVM's.
     *
     * This contract works correctly in both EVM's, because it forwards the minimum value between
     * `address(this).balance` and `msg.value` to the created contract.
     */
    constructor() payable {
        assembly {
            //                       Context Storage Layout
            // | 32-bit |  22-bit  |   32-bit   |  160-bit   |  7-bit  | 3-bit |
            // +-+-+-+-+-+-+-+-+-+-+-+--+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+
            // |  data  | data len |  selector  |  contract  |  depth  | flags | slot 0
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |    data (96-bit)    |             sender (160-bit)            | slot 1
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |                             salt                              | slot 2
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |                             value                             | slot 3
            // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
            // |                          data[128..]                          | start at slot
            // |                             ...                               | 2**64 * depth
            // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
            //
            // If the EVM doesn't support EIP-1153 TRANSIENT STORAGE, then initialize the storage,
            // because the transition from empty to non-empty cost more gas than the transition
            // from non-empty to any, example:
            // - zero to non-zero      20000 gas
            // - non-zero to non-zero: 2900 gas
            // - non-zero to zero:     100 gas
            //
            // OBS: The original values are restored at the end of the execution.
            let placeholder := not(0)
            sstore(0, placeholder)
            sstore(1, placeholder)
            sstore(2, placeholder)
            sstore(3, placeholder)

            // slots used when `context.data.length > 16`
            // sstore(0x10000000000000000, placeholder)
            // sstore(0x10000000000000001, placeholder)
            // sstore(0x10000000000000002, placeholder)
            // sstore(0x10000000000000003, placeholder)
        }
    }

    /**
     * @dev This code must be compatible with `shangai` and `cancun` hardforks, so the `EIP-1153` opcodes must
     * only be used when the EVM supports it, to do accomplish that, this contract calls itself and check the
     * `TSTORE` and `TLOAD` opcode support, this check is done dynamically in case the EVM supports it in the future.
     *
     * @notice inline assembly is used for 3 main reason:
     * 1. Guarantee the opcode `MCOPY` isn't called, once it is only supported by `cancun`.
     * 2. Guarantee an constant and predicatable gas cost, this contract heavily uses branchless code.
     * 3. Optimized code, to reduce the gas cost of the contract.
     *
     * `Solidity` was chosen over `Yul` for portability and better developer experience, once currently you can't import
     * Yul code in Solidity.
     */
    fallback() external payable {
        assembly {
            // If the contracts calls itself, then is for check whether EIP-1153
            // transient storage is supported or not.
            // This check is done dynamically for each call, because even if the EVM
            // doesn't support this opcode right now, it may support it in the future.
            if eq(caller(), address()) { return(0, tload(address())) }

            // ------- BITFLAGS -------
            //         HAS_DATA = 0x01
            //     HAS_CALLBACK = 0x02
            //       IS_CREATE3 = 0x04
            //  SUPPORT_EIP1153 = 0x08
            // ------------------------
            let bitflags

            // Check if this EVM supports EIP-1153 TRANSIENT STORAGE.
            // Obs: This call cost 300 gas if the EVM doesn't support EIP-1153, and 143 gas if it supports.
            bitflags := staticcall(300, address(), 0, 0, 0, 0)

            let valid
            {
                let selector := shr(0xe0, calldataload(0))

                // `function context() external view returns (Context memory)`
                if eq(selector, 0xd0496d6a) {
                    if callvalue() { revert(0, 0) }

                    let ctx0, ctx1, salt, value
                    {
                        switch bitflags
                        case 0 {
                            ctx0 := sload(0)
                            ctx1 := sload(1)
                            salt := sload(2)
                            value := 0
                            let has_context := iszero(eq(ctx0, not(0)))
                            if and(ctx0, has_context) { value := sload(3) }
                            ctx0 := mul(ctx0, has_context)
                            ctx1 := mul(ctx1, has_context)
                            salt := mul(salt, has_context)
                            value := mul(value, has_context)
                        }
                        default {
                            ctx0 := tload(0)
                            ctx1 := tload(1)
                            salt := tload(2)
                            value := tload(3)
                            let has_context := gt(and(ctx0, 0x03f8), 0)
                            ctx0 := mul(ctx0, has_context)
                            ctx1 := mul(ctx1, has_context)
                            salt := mul(salt, has_context)
                            value := mul(value, has_context)
                        }
                    }

                    // Decode `call_flags`.
                    //   IS_CREATE3 := 0x04
                    // HAS_CALLBACK := 0x02
                    //    HAS_VALUE := 0x01
                    let call_flags := and(ctx0, 0x07)
                    let depth := and(shr(3, ctx0), 0x7f)
                    let contract_addr := and(shr(10, ctx0), 0xffffffffffffffffffffffffffffffffffffffff)
                    let callback_selector := shl(224, shr(170, ctx0))
                    let data_len := and(shr(202, ctx0), 0x3fffff)
                    let data := or(shl(160, shr(160, ctx1)), shl(128, shr(224, ctx0)))
                    let sender := and(ctx1, 0xffffffffffffffffffffffffffffffffffffffff)

                    // discard `HAS_VALUE` flag
                    call_flags := shr(1, call_flags)

                    // Store `Context` in memory following Solidity ABI encoding
                    mstore(0x0000, 0x20) // offset
                    mstore(0x0020, contract_addr) // contract_address
                    mstore(0x0040, sender) // sender
                    mstore(0x0060, depth) // call depth
                    mstore(0x0080, shr(1, call_flags)) // kind (0 for CREATE2, 1 for CREATE3)
                    mstore(0x00a0, and(1, call_flags)) // hasCallback
                    mstore(0x00c0, callback_selector) // callbackSelector
                    mstore(0x00e0, value) // value
                    mstore(0x0100, salt) // salt
                    mstore(0x0120, 0x0120) // offset
                    mstore(0x0140, data_len) // data_len
                    mstore(0x0160, data) // initializer_val

                    switch bitflags
                    case 0 {
                        // Copy `data[16..]` from storage to memory
                        for {
                            let end := add(0x0160, data_len)
                            let ptr := 0x170
                            let offset := shl(64, depth)
                        } lt(ptr, end) {
                            ptr := add(ptr, 0x20)
                            offset := add(offset, 0x01)
                        } { mstore(ptr, sload(offset)) }
                    }
                    default {
                        // Copy `data[16..]` from transient storage to memory
                        for {
                            let end := add(0x0160, data_len)
                            let ptr := 0x170
                            let offset := shl(64, depth)
                        } lt(ptr, end) {
                            ptr := add(ptr, 0x20)
                            offset := add(offset, 0x01)
                        } { mstore(ptr, tload(offset)) }
                    }

                    // Remove any non-zero padding
                    mstore(add(0x0160, data_len), 0)
                    // Return an 32-byte aligned result
                    return(0x00, add(0x0160, and(add(data_len, 0x1f), 0xffffffffffffffe0)))
                }

                // Check if the method contains an `callback`
                // - function create2(uint256 salt, bytes calldata creationCode, bytes calldata data, bytes calldata callback)
                // - function create3(uint256 salt, bytes calldata creationCode, bytes calldata data, bytes calldata callback)
                let has_callback := or(eq(selector, 0xe45c31ee), eq(selector, 0x1f7a56c0))

                // Check if the method contains an `data` but not an `callback`
                // - function create2(uint256 salt, bytes calldata creationCode, bytes calldata data)
                // - function create3(uint256 salt, bytes calldata creationCode, bytes calldata data)
                let has_data := or(has_callback, or(eq(selector, 0x579da0bf), eq(selector, 0xb5164ce9)))

                // Check if the method doesn't contain an `data` or `callback`
                // - function create2(uint256 salt, bytes calldata creationCode)
                // - function create3(uint256 salt, bytes calldata creationCode)
                let is_simple := or(eq(selector, 0xfe984079), eq(selector, 0x53ca4842))

                // Check if the selector is `create3(...)`
                let is_create3 := or(or(eq(selector, 0x53ca4842), eq(selector, 0xb5164ce9)), eq(selector, 0x1f7a56c0))

                // Check if the selector is valid
                valid := or(is_simple, has_data)
                {
                    // Check the minimal calldatasize when `data` or `callback` are provided
                    let min_calldatasize := add(0x43, shl(5, add(has_data, has_callback)))
                    valid := and(valid, gt(calldatasize(), min_calldatasize))
                }

                // Set `deploy_proxy`, `has_callback` and `has_data` flags
                bitflags := or(shl(1, bitflags), is_create3)
                bitflags := or(shl(1, bitflags), has_callback)
                bitflags := or(shl(1, bitflags), has_data)
            }

            let initializer_ptr
            let initializer_len
            {
                // initializer_ptr <= 0xffffffffffffffff
                initializer_ptr := calldataload(0x44)
                let has_data := and(bitflags, 0x01)
                let valid_initializer := and(has_data, lt(initializer_ptr, 0x010000000000000000))
                // initializer_ptr > (has_callback ? 0x7f : 0x5f)
                {
                    let has_callback := shl(4, and(bitflags, 0x02))
                    valid_initializer := and(valid_initializer, gt(initializer_ptr, add(has_callback, 0x5f)))
                }

                // calldatasize > (initializer_ptr + 0x1f)
                initializer_ptr := add(initializer_ptr, 0x04)
                valid_initializer := and(valid_initializer, slt(add(initializer_ptr, 0x1f), calldatasize()))

                // initializer_len <= 0x3fffff
                initializer_len := calldataload(initializer_ptr)
                valid_initializer := and(valid_initializer, lt(initializer_len, 0x400000))
                initializer_ptr := add(initializer_ptr, 0x20)

                // (initializer_ptr + initializer_len + 0x20) >= calldatasize
                valid_initializer :=
                    and(valid_initializer, iszero(gt(add(initializer_ptr, initializer_len), calldatasize())))

                {
                    // Set initializer_ptr and initializer_len to zero if there's no initializer
                    valid_initializer := and(valid_initializer, has_data)
                    initializer_ptr := mul(initializer_ptr, valid_initializer)
                    initializer_len := mul(initializer_len, valid_initializer)

                    // If the call has no initializer, it is always valid.
                    valid_initializer := or(valid_initializer, iszero(has_data))
                }
                valid := and(valid, valid_initializer)
            }

            {
                // callback_ptr <= 0xffffffffffffffff
                let callback_ptr := calldataload(0x64)
                let has_callback := and(shr(1, bitflags), 1)
                let valid_callback := and(has_callback, lt(callback_ptr, 0x010000000000000000))
                // callback_ptr > 0x7f
                valid_callback := and(valid_callback, gt(callback_ptr, 0x7f))

                // calldatasize > (callback_ptr + 0x1f)
                callback_ptr := add(callback_ptr, 0x04)
                valid_callback := and(valid_callback, slt(add(callback_ptr, 0x1f), calldatasize()))

                // callback_len <= 0xffffffffffffffff
                let callback_len := calldataload(callback_ptr)
                valid_callback := and(valid_callback, lt(callback_len, 0x010000000000000000))
                callback_ptr := add(callback_ptr, 0x20)

                // (callback_ptr + callback_len + 0x20) >= calldatasize
                valid_callback := and(valid_callback, iszero(gt(add(callback_ptr, callback_len), calldatasize())))

                // If the call has no callback, it is always valid.
                valid_callback := or(valid_callback, iszero(has_callback))
                valid := and(valid, valid_callback)
            }

            // creationcode_ptr <= 0xffffffffffffffff
            let creationcode_ptr := calldataload(0x24)
            valid := and(valid, lt(creationcode_ptr, 0x010000000000000000))
            // creationcode_ptr >= 0x3f
            {
                let data_and_callback := and(bitflags, 0x03)
                data_and_callback := xor(data_and_callback, shr(1, data_and_callback))
                valid := and(valid, gt(creationcode_ptr, add(0x3f, shl(5, data_and_callback))))
            }

            // calldatasize > (creationcode_ptr + 0x1f)
            creationcode_ptr := add(creationcode_ptr, 0x04)
            valid := and(valid, slt(add(creationcode_ptr, 0x1f), calldatasize()))

            // creationcode_len <= 0xffffffffffffffff
            let creationcode_len := calldataload(creationcode_ptr)
            valid := and(valid, lt(creationcode_len, 0x010000000000000000))
            creationcode_ptr := add(creationcode_ptr, 0x20)

            // (creationcode_ptr + creationcode_len + 0x20) <= calldatasize
            valid := and(valid, iszero(gt(add(creationcode_ptr, creationcode_len), calldatasize())))

            // creationcode_len > 0
            valid := and(valid, gt(creationcode_len, 0))

            if iszero(valid) { revert(0, 0) }

            // Load previous context and salt, they are restored at the end of the execution,
            // to guarantee nested calls to this contract are consistent.
            let prev_slot0 := 0
            let prev_slot1 := 0
            let prev_salt := 0
            let prev_value := 0
            switch shr(3, bitflags)
            case 0 {
                // Load `ctx` and `salt` from the storage
                let ctx0 := sload(0)
                if xor(ctx0, not(0)) {
                    prev_slot0 := ctx0
                    prev_slot1 := sload(1)
                    prev_salt := sload(2)
                    prev_value := sload(3)
                }
            }
            default {
                // Load `ctx` and `salt` from transient storage
                prev_slot0 := tload(0)
                prev_slot1 := tload(1)
                prev_salt := tload(2)
                prev_value := tload(3)
            }

            // Workaround for substrate evm based chains, where `selfbalance` can be less than
            // `callvalue` if this contract has no existential deposit.
            //
            // The following code is a branchless version of the ternary operator, equivalent to:
            // address(this).balance < msg.value ? address(this).balance : msg.value
            let value := xor(callvalue(), mul(xor(selfbalance(), callvalue()), lt(selfbalance(), callvalue())))

            {
                // Decode the previous `depth` from slot 0.
                let depth := and(shr(3, prev_slot0), 0x7f)

                // The `depth` must be less than 127, which is the maximum number of nested calls before overflow.
                // obs: probably impossible to reach this limit, due EIP-150 `all but one 64th`.
                // - reference: https://eips.ethereum.org/EIPS/eip-150
                if gt(depth, 0x7e) {
                    // revert CallStackOverflow()
                    mstore(0x00, 0x41f739de)
                    revert(0x1c, 0x04)
                }
                depth := add(depth, 0x01)

                // ------------ Static Memory Layout ------------
                // 0x00        -> final contract address
                // 0x20        -> proxy contract address when using `create3`.
                // 0x40        -> current call depth
                // 0x60        -> creation code hash
                // 0x80        -> memory offset of the provided creation code
                //
                // Obs: the memory layout above is ignored for revert messages, also can be
                // be used by a different purpose before it's final value is assigned.

                // Copy `creationCode` to memory
                calldatacopy(0x80, creationcode_ptr, creationcode_len)

                ////////////////////////////////////////////////////////////////////
                //                      Compute CREATE2 address                   //
                ////////////////////////////////////////////////////////////////////
                mstore(0x00, or(address(), 0xff0000000000000000000000000000000000000000))
                mstore(0x20, calldataload(0x04))
                // 0xda812570be8257354a14ed469885e4d206be920835861010301b25f5c180427a == keccak256(proxyCreationCode)
                let creationcode_hash := keccak256(0x80, creationcode_len)
                let is_create3 := and(shr(2, bitflags), 1)
                mstore(0x60, creationcode_hash)
                creationcode_hash :=
                    xor(
                        creationcode_hash,
                        mul(
                            xor(0xda812570be8257354a14ed469885e4d206be920835861010301b25f5c180427a, creationcode_hash),
                            is_create3
                        )
                    )
                mstore(0x40, creationcode_hash)
                // Compute the final address
                let addr := and(keccak256(11, 85), 0xffffffffffffffffffffffffffffffffffffffff)

                // Validate address and initcode
                {
                    // The proxy creation code is reserved only for `create3` methods
                    let invalid_init_code :=
                        and(
                            iszero(is_create3),
                            eq(creationcode_hash, 0xda812570be8257354a14ed469885e4d206be920835861010301b25f5c180427a)
                        )
                    // The contract must not exist
                    let contract_exists := extcodesize(addr)

                    if or(contract_exists, invalid_init_code) {
                        // 0xb8bcb0c9 == bytes4(keccak256("ReservedInitCode()"))
                        // 0xc5644373 == bytes4(keccak256("ContractAlreadyExists(address)"))
                        // 0x7dd8f3ba == 0xb8bcb0c9 ^ 0xc5644373
                        let sig := xor(0xb8bcb0c9, mul(0x7dd8f3ba, invalid_init_code))
                        let len := add(0x04, shl(5, iszero(invalid_init_code)))
                        mstore(0x00, sig)
                        mstore(0x20, addr)
                        revert(0x1c, len)
                    }
                }

                // Store `create2` address at 0x20, this can be either the final address
                // when using `create2`, or the proxy address when using `create3`.
                mstore(0x20, addr)

                ////////////////////////////////////////////////////////////////////
                //                      Compute CREATE3 address                   //
                ////////////////////////////////////////////////////////////////////
                mstore(0x40, or(0xd694000000000000000000000000000000000000000001, shl(8, addr)))
                let proxy_addr := and(keccak256(0x49, 23), 0xffffffffffffffffffffffffffffffffffffffff)

                // Select the final contract address
                addr := xor(addr, mul(xor(proxy_addr, addr), is_create3))

                // Store final contract address at 0x00
                mstore(0, addr)

                // Store the depth at 0x40
                mstore(0x40, depth)

                ////////////////////////////////////////////////////////////////////
                //                           UPDATE CONTEXT                       //
                ////////////////////////////////////////////////////////////////////
                //
                //                       Context Storage Layout
                // | 32-bit |  22-bit  |   32-bit   |  160-bit   |  7-bit  | 3-bit |
                // +-+-+-+-+-+-+-+-+-+-+-+--+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+
                // |  data  | data len |  selector  |  contract  |  depth  | flags | slot 0
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |    data (96-bit)    |             sender (160-bit)            | slot 1
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                             salt                              | slot 2
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                             value                             | slot 3
                // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
                // |                          data[128..]                          | start at slot
                // |                             ...                               | 2**64 * depth
                // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
                let slot0
                // Encode `data[96..128]` (32 bits)
                {
                    let has_data := and(bitflags, 0x01)
                    let data := shr(224, shl(96, calldataload(initializer_ptr)))
                    data := mul(data, has_data)
                    slot0 := data
                }
                // Encode data_len (22 bits)
                // Obs: validated previously, so is always less than 2**22
                slot0 := or(shl(22, slot0), initializer_len)
                // Encode selector (32 bits)
                {
                    let callback_ptr := add(calldataload(0x64), 0x24)
                    let callback_selector := shr(224, calldataload(callback_ptr))
                    let has_callback := and(shr(1, bitflags), 1)
                    callback_selector := mul(callback_selector, has_callback)
                    slot0 := or(shl(32, slot0), callback_selector)
                }
                // Encode contractAddress (160 bits)
                slot0 := or(shl(160, slot0), addr)
                // Encode depth (7 bits)
                slot0 := or(shl(7, slot0), depth)
                // Encode bitflags (3 bits)
                slot0 := or(shl(3, slot0), or(and(bitflags, 0x06), gt(value, 0)))

                // Encode `data[..96]` (96 bit) + sender (160 bit)
                let slot1 := or(shl(160, shr(160, calldataload(initializer_ptr))), caller())
                // Encode salt (256 bits)
                let salt := calldataload(0x04)

                // Store the new Context in the transient storage or storage.
                let support_eip1153 := and(bitflags, 0x08)
                switch support_eip1153
                case 0 {
                    // Store the context in the storage, skip `value` if zero.
                    sstore(0, slot0)
                    sstore(1, slot1)
                    sstore(2, salt)
                    // When `msg.value > 0`, then the first bit of `flags` is set, so no need to store this value (saves ~2900 gas).
                    if value { sstore(3, value) }

                    // If `data.length > 16`, then store the remaining bytes in the storage,
                    // starting at index `2**64 * depth`.
                    for {
                        let end := add(initializer_ptr, initializer_len)
                        let ptr := add(initializer_ptr, 16)
                        let offset := shl(64, depth)
                    } lt(ptr, end) {
                        ptr := add(ptr, 0x20)
                        offset := add(offset, 0x01)
                    } { sstore(offset, calldataload(ptr)) }
                }
                default {
                    // Store the context in the EIP-1153 Transient Storage.
                    // obs: don't need to skip value once the gas cost is negligible (~100 gas).
                    tstore(0, slot0)
                    tstore(1, slot1)
                    tstore(2, salt)
                    tstore(3, value)

                    // If `data.length > 16`, then store the remaining bytes in the transient storage,
                    // starting at index `2**64 * depth`.
                    for {
                        let end := add(initializer_ptr, initializer_len)
                        let ptr := add(initializer_ptr, 16)
                        let offset := shl(64, depth)
                    } lt(ptr, end) {
                        ptr := add(ptr, 0x20)
                        offset := add(offset, 0x01)
                    } { tstore(offset, calldataload(ptr)) }
                }
            }

            // Create contract using `create2` or `create3`
            switch and(bitflags, 0x04)
            case 0 {
                /////////////////
                //   CREATE2   //
                /////////////////

                // Deploy contract or Proxy, depending if `is_create3` is enabled.
                let contract_addr :=
                    create2(mul(value, iszero(and(bitflags, 0x06))), 0x80, creationcode_len, calldataload(0x04))

                // Computed address and actual address must match
                if or(iszero(contract_addr), xor(contract_addr, mload(0))) {
                    // 0x04a5b3ee -> Create2Failed()
                    mstore(0x00, 0x04a5b3ee)
                    revert(0x1c, 0x04)
                }
            }
            default {
                /////////////////
                //   CREATE3   //
                /////////////////

                // Create3Proxy creation code
                // 0x763318602e57363d3d37363d34f080915215602e57f35bfd6017526460203d3d7360a01b33173d5260306007f3:
                //     0x00  0x67  0x763318602e..  PUSH23 0x3318.. 0x3318602e57363d3d37363d34f080915215602e57f35bfd
                //     0x01  0x3d  0x3d            PUSH1 0x58      23 0x3318602e57363d3d37363d34f080915215602e57f35bfd
                //     0x01  0x3d  0x3d            MSTORE
                //     0x03  0x52  0x5260203d3d..  PUSH5 0x60203.. 0x60203d3d73
                //     0x04  0xf3  0x6008          PUSH1 0xa0      160 0x60203d3d73
                //     0x05  0x60  0x6018          SHL             0x60203d3d730000000000000000000000000000000000000000
                //     0x06  0x3d  0x3d            CALLER          addr 0x60203d3d730000000000000000000000000000000000000000
                //     0x08  0xf3  0xf3            OR              0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
                //     0x09  0x60  0x6018          RETURNDATASIZE  0 0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
                //     0x04  0xf3  0x6008          PUSH1 0x30      48
                //     0x04  0xf3  0x6008          PUSH1 0x07      7 48
                //     0x14  0x3d  0x3d            RETURN

                // Create3Proxy runtime code
                // 0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX3318602e57363d3d37363d34f080915215602e57f35bfd
                //     0x00  0x60  0x6020          PUSH1 0x20      32
                //     0x03  0x3d  0x3d            RETURNDATASIZE  0 32
                //     0x03  0x3d  0x3d            RETURNDATASIZE  0 0 32
                //     0x00  0x60  0x74XXXXXX..    PUSH20 XXXXXXX  xxxx 0 0 32
                //     0x01  0x3d  0x3d            CALLER          caller xxxx 0 0 32
                //     0x02  0x3d  0x3d            XOR             fail 0 0 32
                //     0x02  0x3d  0x3d            PUSH1 0x2e      46 fail 0 0 32
                // ,=< 0x07  0xf0  0xf0            JUMPI           0 0 32
                // |   0x03  0x3d  0x3d            CALLDATASIZE    cls 0 0 32
                // |   0x04  0x36  0x36            RETURNDATASIZE  0 cls 0 0 32
                // |   0x05  0x3d  0x3d            RETURNDATASIZE  0 0 cls 0 0 32
                // |   0x06  0x34  0x34            CALLDATACOPY    0 0 32
                // |   0x07  0xf0  0xf0            CALLDATASIZE    cls 0 0 32
                // |   0x07  0xf0  0xf0            RETURNDATASIZE  0 cls 0 0 32
                // |   0x07  0xf0  0xf0            CALLVALUE       val 0 cls 0 0 32
                // |   0x07  0xf0  0xf0            CREATE          addr 0 0 32
                // |   0x07  0xf0  0xf0            JUMPDEST
                // |   0x07  0xf0  0xf0            DUP1            addr addr 0 0 32
                // |   0x03  0x37  0x37            SWAP2           0 addr addr 0 32
                // |   0x03  0x37  0x37            MSTORE          addr 0 32
                // |   0x04  0x36  0x36            ISZERO          fail 0 32
                // |   0x03  0x37  0x37            PUSH1 0x2e      46 fail 0 32
                // |=< 0x03  0x37  0x37            JUMPI           0 32
                // |   0x03  0x37  0x37            RETURN
                // `=> 0x03  0x37  0x37            JUMPDEST
                //     0x03  0x37  0x37            REVERT

                // Deploy the `Create3Proxy`
                let proxy_addr
                {
                    // Save the current memory state, to restore it after the proxy deployment.
                    let mem00 := mload(0x00)
                    let mem20 := mload(0x20)
                    {
                        // Store `Create3Proxy` initcode in memory.
                        mstore(0x0d, 0x7360a01b33173d5260306007f3)
                        mstore(0x00, 0x763318602e57363d3d37363d34f080915215602e57f35bfd6017526460203d3d)
                        // Deploy contract or Proxy, depending if `is_create3` is enabled.
                        proxy_addr := create2(mul(value, iszero(and(bitflags, 0x06))), 0x00, 45, calldataload(0x04))
                    }
                    // Restore the memory state
                    mstore(0x00, mem00)
                    mstore(0x20, mem20)
                }

                // return an error if failed to create `Create3Proxy`.
                if iszero(and(eq(proxy_addr, mload(0x20)), eq(extcodesize(proxy_addr), 48))) {
                    // revert Create3Failed()
                    mstore(0x00, 0x08fde50a)
                    revert(0x1c, 0x04)
                }

                // Save the computed address in the stack
                // once the `Create3Proxy` will override the 0x00 memory location.
                let computed_addr := mload(0)

                // Call the `Create3Proxy` to deploy the desired contract at deterministic address.
                let success :=
                    call(
                        gas(),
                        proxy_addr,
                        mul(value, iszero(and(bitflags, 0x02))), // Check if the flag HAS_CALLBACK is disabled
                        0x80,
                        creationcode_len,
                        0x00,
                        0x20
                    )

                // Comapare computed address and actual address
                if or(iszero(success), xor(computed_addr, mload(0))) {
                    // 0x08fde50a -> Create3Failed()
                    mstore(0x00, 0x08fde50a)
                    revert(0x1c, 0x04)
                }
            }

            // Emit `ContractCreated` event and call `callback` if provided
            {
                let has_callback := and(shr(1, bitflags), 1)
                let callback_ptr := add(calldataload(0x64), 0x04)
                let callback_len := calldataload(callback_ptr)
                callback_ptr := add(callback_ptr, 0x20)
                callback_ptr := mul(callback_ptr, has_callback)
                callback_len := mul(callback_len, has_callback)

                {
                    // Copy data to memory
                    calldatacopy(0x80, initializer_ptr, initializer_len)

                    // Calculate data hash
                    let data_hash := keccak256(0x80, initializer_len)
                    {
                        let has_data := and(bitflags, 0x01)
                        data_hash := mul(data_hash, and(bitflags, 0x01))
                    }

                    // Copy callback to memory
                    calldatacopy(0x80, callback_ptr, callback_len)

                    // Calculate callback hash
                    {
                        let callback_hash := keccak256(0x80, callback_len)
                        callback_hash := mul(callback_hash, has_callback)
                        mstore(0x20, callback_hash)
                    }

                    // emit ContractCreated(contractAddress, creationCodeHash, salt, dataHash, codeHash, callbackHash, depth, value)
                    let creation_code_hash := mload(0x60)
                    mstore(0x60, value)
                    let contract_addr := mload(0)
                    mstore(0x00, extcodehash(contract_addr))
                    log4(0x00, 0x80, contract_addr, creation_code_hash, calldataload(0x04), data_hash)
                    mstore(0x00, contract_addr)
                }

                // Call `callback` if provided
                if has_callback {
                    // Call initializer
                    if iszero(call(gas(), mload(0), value, 0x80, callback_len, 0, 0)) {
                        mstore(0x00, 0x30b9b6dd)
                        // error offset
                        mstore(0x20, 0x20)
                        // error length
                        mstore(0x40, returndatasize())
                        // cleanup padding bytes, in case it has initializer bytes
                        mstore(add(0x60, returndatasize()), 0x00)
                        // Copy revert data to memory
                        returndatacopy(0x60, 0, returndatasize())
                        // revert(data + padding)
                        revert(0x1c, add(and(add(returndatasize(), 31), 0xffffffffffffffe0), 0x44))
                    }
                }
            }

            // Restore previous ctx and salt
            // Obs: the logic for restore the state is different for storage and transient storage,
            // because for storage, the `zero to non-zero` transition use more gas than the `non-zero to non-zero`.
            switch shr(3, bitflags)
            case 0 {
                // Cleanup `data` from the storage, the following code resets any zero value to 2**256 - 1.
                if and(bitflags, 0x01) {
                    let data_ptr := add(calldataload(0x44), 0x04)
                    let data_len := calldataload(data_ptr)
                    data_ptr := add(data_ptr, 0x20)
                    for {
                        let end := add(data_ptr, data_len)
                        let ptr := add(data_ptr, 16)
                        let offset := shl(64, and(shr(3, sload(0)), 0x7f))
                    } lt(ptr, end) {
                        ptr := add(ptr, 0x20)
                        offset := add(offset, 0x01)
                    } { if iszero(calldataload(ptr)) { sstore(offset, not(0)) } }
                }

                let is_empty := iszero(or(or(prev_slot0, prev_slot1), prev_salt))
                let mask := sub(0, is_empty)
                sstore(0, or(prev_slot0, mask))
                sstore(1, or(prev_slot1, mask))
                sstore(2, or(prev_salt, mask))
                if value { sstore(3, or(prev_value, mask)) }
            }
            default {
                tstore(0, prev_slot0)
                tstore(1, prev_slot1)
                tstore(2, prev_salt)
                tstore(3, prev_value)
            }

            // return the created contract address
            return(0, 0x20)
        }
    }
}
