// SPDX-License-Identifier: MIT
/*
 * Universal Factory Contract
 * This standard defines an universal factory smart contract where any address (contract or regular account) can
 * deploy and reserve deterministic contract addresses in any network.
 *
 * Written in 2024 by Lohann Paterno Coutinho Ferreira <developer@lohann.dev>.
 *
 * Universal Factory is derived from EIP-2470 and EIP-3171, with an additional feature that allows the contract
 * constructor to read arguments without including it in the bytecode, this way custom arguments can be provided
 * and immutables can be set without influencing the resulting `CREATE2` address.
 * - EIP-2470: https://eips.ethereum.org/EIPS/eip-2470
 * - EIP-3171: https://github.com/ethereum/EIPs/pull/3171
 *
 * This contract is intented to be deployed at the same address on all networks using keyless deployment method.
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

/**
 * @title Universal Factory Contract
 * @author Lohann Paterno Coutinho Ferreira
 * @notice This contract is a factory that allows you to deploy contracts at deterministic addresses in any network.
 *
 * # How it works
 * To pass arbitrary arguments to the contract without influecing resulting address, this contract caches the arguments
 * locally, and provide it to the contract constructor when it calls the `context()` function.
 * - For `cancun` it caches the arguments using the EIP-1153 Transient Storage (~100 gas per word + overhead).
 * - For `shanghai` it caches the arguments using the regular storage (~2900 gas per word + overhead).
 *
 * # Predictable Gas Cost
 * This contract uses many different Branchless Code techniques (most of them develop by the author), so this contract have an very
 * predictable gas overhead in any network (the actual overhead may change depending on the EVM implementation).
 * - For `shanghai` evms, to guarantee an predictable gas cost, it make sure all values stored are different than zero.
 * This is accomplished by hashing the arguments, and use the resulting hash to XOR the bytes before store and after read it.
 * - For `cancun` there's no diffence between storing zero or non-zero values, so the `XOR` step is skipped.
 */
contract UniversalFactory {
    /**
     * @notice The Constructor is payable due Frontier EVM compatibility, once that EVM have the concept
     * of existential deposit (ED), in this evm if you send a balance to a contract without ED, then the
     * ED will be discounted from the contract balance, as result `address(this).balance < msg.value`,
     * which is impossible in standard EVM's clients.
     * - https://github.com/polkadot-evm/frontier/blob/polkadot-v1.11.0/ts-tests/tests/test-balance.ts#L41
     *
     * This contract works correctly in Frontier and standard EVM's, because it forwards the minimum value
     * between `address(this).balance` and `msg.value` to the created contract.
     */
    constructor() payable {
        assembly {
            //                       Context Storage Layout
            // | 32-bit |  22-bit  |   32-bit   |  160-bit   |  7-bit  | 3-bit |
            // +-+-+-+-+-+-+-+-+-+-+-+--+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+
            // |  args  | args.len |  selector  |  contract  |  depth  | flags | offset: 0
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |   args[..12] (96-bit)  |           sender (160-bit)           | offset: 1
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |                             salt                              | offset: 2
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |                             value                             | offset: 3
            // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
            // |                       keccak256(args)*                        | offset: 2**64 * depth
            // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // |                          args[16..]                           | offset: 2**64 * depth + 1
            // |                             ...                               | length: (args.length + 15) / 32
            // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
            //
            // - For `cancun`, the context is stored in `transient storage` using the `TSTORE` and `TLOAD` opcodes.
            // - For `shanghai`, the context is stored in `regular storage` using the `SSTORE` and `SLOAD` opcodes.
            //
            // If the EVM doesn't support EIP-1153 TRANSIENT STORAGE, then it initialize the storage,
            // because the transition from empty to non-empty cost more gas than the transition
            // from non-empty to any, example:
            // - zero to non-zero      20000 gas
            // - non-zero to non-zero: 2900 gas
            // - non-zero to zero:     100 gas
            //
            // The original values are restored at the end of the execution, except for `args`, which don't need to be restored
            // once they are stored in an unique offset per call depth.
            //
            // # Motivation behind `keccak256(args)`.
            // Different than `EIP-1153` transient storage, the regular storage is persisted between transactions, so to
            // guarantee an predictable gas cost, and prevent the previous calls to increase the gas cost of future calls, is
            // necessary to guarantee that all values stored are different than zero. The way we enforce this is by computing
            // the keccak256 of `args`, and use it to XOR the bytes before store and after read it, so is infeseable
            // to create an `argument` that can have 256 consecutive zeros when stored.
            let placeholder := not(0)
            sstore(0, placeholder)
            sstore(1, placeholder)
            sstore(2, placeholder)
            sstore(3, placeholder)

            // Notice is possible to send funds to this contract address before it is deployed. To guarantee this contract
            // doesn't hold any funds, we sent the whole balance to an `GiveAway` contract, which is deployed below.

            // GiveAway contract bytecode
            // 0x34600c573d3d3d3d47335af15b00:
            //     0x00  0x34      CALLVALUE       val
            //     0x01  0x600c    PUSH1 0x0c      12 val
            //  ,=<0x03  0x57      JUMPI
            //  |  0x04  0x3d      RETURNDATASIZE  0
            //  |  0x05  0x3d      RETURNDATASIZE  0 0
            //  |  0x06  0x3d      RETURNDATASIZE  0 0 0
            //  |  0x07  0x3d      RETURNDATASIZE  0 0 0 0
            //  |  0x08  0x47      SELFBALANCE     balance 0 0 0 0
            //  |  0x09  0x33      CALLER          addr balance 0 0 0 0
            //  |  0x0a  0x5a      GAS             gas addr balance 0 0 0 0
            //  |  0x0b  0xf1      CALL            suc
            //  `=>0x0c  0x5b      JUMPDEST        suc
            //     0x0d  0x00      STOP
            mstore(0x00, 0x6d34600c573d3d3d3d47335af15b003d52600e6012f3)
            pop(create(selfbalance(), 0x0a, 22))
        }
    }

    /**
     * @dev This contract must be compatible with `shanghai` and `cancun` hardforks, the `EIP-1153` opcodes must
     * only be used when the EVM supports `cancun`, to accomplish that, this contract calls itself and check the
     * `TLOAD` opcode support, this check is done dynamically in case the EVM supports it in the future.
     *
     * @notice inline assembly is used for 3 main reason:
     * 1. Guarantee the opcode `MCOPY` isn't called, once it is only supported by `cancun`.
     * 2. Guarantee an predictable gas cost, this contract uses various branchless code techniques develop by the author.
     * 3. Optimized code, to reduce the gas cost of the contract.
     *
     * `Solidity` was chosen over pure `Yul` due portability and developer experience reasons, once currently you can't
     * import Yul code in Solidity, also in most block explorers you can't verify/publish YUL code.
     */
    fallback() external payable {
        // ---------------- Static Memory Layout ---------------
        // offset | description
        // -------|---------------------------------------------
        // 0x0000 | final contract address
        // 0x0020 | `Create3Proxy` proxy contract address.
        // 0x0040 | keccak256(creationCode)
        // 0x0060 | keccak256(arguments)
        // 0x0080 | keccak256(callback)
        // 0x00a0 | current depth
        // 0x00c0 | creationCode.offset
        // 0x00e0 | creationCode.length
        // 0x0100 | arguments.offset
        // 0x0120 | arguments.length
        // 0x0140 | callback.offset
        // 0x0160 | callback.length
        // 0x0180 | previous slot 0
        // 0x01a0 | previous slot 1
        // 0x01c0 | previous salt
        // 0x01e0 | previous value
        // 0x0200 | dynamic memory, ex: creationCode, arguments and callback.
        //
        // Obs: the memory layout above is ignored for revert messages.
        assembly {
            // If the contracts calls itself, then is for check whether EIP-1153
            // transient storage is supported or not.
            // This check is done dynamically for each call, because even if the EVM
            // doesn't support this opcode right now, it may support it in the future.
            if eq(caller(), address()) {
                mstore(0x00, tload(0))
                mstore(0x20, tload(1))
                mstore(0x40, tload(2))
                mstore(0x60, tload(3))

                // obs: for debugging purposes, you can change this to `revert(0,0)`
                // to disable EIP-1153 support.
                return(0, 0x80)
            }

            // ------- BITFLAGS -------
            //    HAS_ARGUMENTS = 0x01
            //     HAS_CALLBACK = 0x02
            //       IS_CREATE3 = 0x04
            //  SUPPORT_EIP1153 = 0x08
            // ------------------------
            let bitflags
            {
                {
                    let selector := shr(0xe0, calldataload(0))

                    ///////////////////////////////////////////////////////////////
                    // function context() external view returns (Context memory) //
                    ///////////////////////////////////////////////////////////////
                    // This selector is checked first to reduce the gas overhead, once this is expected to
                    // be called more frequently.
                    if eq(selector, 0xd0496d6a) {
                        // No value can be sent once it is a view function. It also make sure the call has
                        // sufficient gas, to prevent false negatives when checking for EIP-1153 support.
                        if or(callvalue(), lt(gas(), 3000)) { revert(0, 0) }

                        //////////////////////////
                        // Load current context //
                        //////////////////////////
                        // First try to retrieve the context using EIP-1153 TRANSIENT STORAGE, the result
                        // is automatically stored in corresponding static memory.
                        // Obs: This call use all 2000 gas if the EVM doesn't support EIP-1153, and 472 gas
                        // if it supports. We provide an extra gas margin in case those opcodes change their
                        // gas cost in the future.
                        let support_eip1153 := staticcall(2000, address(), 0, 0, 0x0180, 0x80)

                        // if it doesn't support EIP-1153, then load the context from storage.
                        if iszero(support_eip1153) {
                            let slot0 := sload(0)
                            if xor(slot0, not(0)) {
                                mstore(0x0180, slot0)
                                mstore(0x01a0, sload(1))

                                // Once the `salt` zero is very common, we XOR it with the slot0 to reduce the likelihood
                                // of storing a zero value, otherwise using the salt zero ended up using more gas than
                                // using a non-zero salt, which is inconvenient but not an issue at all.
                                // Notice the previous salt is always restored at the end of the execution. So this value
                                // cannot influence any subsequent contract creation gas cost.
                                mstore(0x01c0, xor(sload(2), slot0))

                                // Only load the value if the `HAS_VALUE` flag is set.
                                // This flag is used to avoid storing a zero value in the storage, it also saves one storage
                                // write/read when no value is provided (saves ~2900 gas).
                                let has_value := and(slot0, 0x01)
                                if has_value { mstore(0x01e0, sload(3)) }
                            }
                        }

                        // Load context from static memory
                        let slot0 := mload(0x0180)
                        let slot1 := mload(0x01a0)
                        let salt := mload(0x01c0)
                        let value := mload(0x01e0)

                        // Decode `call_flags`.
                        //   IS_CREATE3 := 0x04
                        // HAS_CALLBACK := 0x02
                        //    HAS_VALUE := 0x01
                        let call_flags := and(slot0, 0x07)
                        let depth := and(shr(3, slot0), 0x7f)
                        let contract_addr := and(shr(10, slot0), 0xffffffffffffffffffffffffffffffffffffffff)
                        let callback_selector := shl(224, shr(170, slot0))
                        let args_len := and(shr(202, slot0), 0x3fffff)
                        let data := or(shl(160, shr(160, slot1)), shl(128, shr(224, slot0)))
                        let sender := and(slot1, 0xffffffffffffffffffffffffffffffffffffffff)

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
                        mstore(0x0140, args_len) // data_len
                        mstore(0x0160, data) // arguments[..16]

                        // If the args.length > 16, then copy the rest of the arguments to memory.
                        switch support_eip1153
                        case 0 {
                            if gt(args_len, 16) {
                                // Copy `data[16..]` from storage to memory
                                for {
                                    let end := add(0x0160, args_len)
                                    let ptr := 0x170
                                    let offset := shl(64, depth)
                                    let args_hash := sload(offset)
                                    offset := add(offset, 0x01)
                                } lt(ptr, end) {
                                    ptr := add(ptr, 0x20)
                                    offset := add(offset, 0x01)
                                } { mstore(ptr, xor(sload(offset), args_hash)) }
                            }
                        }
                        default {
                            // Copy `data[16..]` from transient storage to memory
                            for {
                                let end := add(0x0160, args_len)
                                let ptr := 0x170
                                let offset := shl(64, depth)
                            } lt(ptr, end) {
                                ptr := add(ptr, 0x20)
                                offset := add(offset, 0x01)
                            } { mstore(ptr, tload(offset)) }
                        }

                        // Remove any non-zero from padding bytes
                        mstore(add(0x0160, args_len), 0)
                        // Return an 32-byte aligned result
                        return(0x00, add(0x0160, and(add(args_len, 0x1f), 0xffffffffffffffe0)))
                    }

                    ///////////////////////////
                    // Validate the selector //
                    ///////////////////////////

                    // The 5 least significant bits of the selectors are unique, this allow an efficient selector
                    // verification using less than 100 gas.
                    // |               FUNCTION             |  SELECTOR  |       suffix  (5-bit)     | index | bitflags |
                    // | create2(bytes32,bytes,bytes,bytes) | 0x8778391e |  0x8778391e & 0x1f == 30  |   26  |    011   |
                    // | create3(bytes32,bytes,bytes,bytes) | 0xac049de2 |  0xac049de2 & 0x1f ==  2  |   27  |    111   |
                    // | create2(bytes32,bytes,bytes)       | 0xce40d339 |  0xce40d339 & 0x1f == 25  |   28  |    001   |
                    // | create3(bytes32,bytes,bytes)       | 0xd2a8169a |  0xd2a8169a & 0x1f == 26  |   29  |    101   |
                    // | create2(bytes32,bytes)             | 0xb9aaf526 |  0xb9aaf526 & 0x1f ==  6  |   30  |    000   |
                    // | create3(bytes32,bytes)             | 0x2af25238 |  0x2af25238 & 0x1f == 24  |   31  |    100   |

                    // Convert the 5-bit suffix into an index using byte lookup.
                    let index
                    {
                        let suffix := and(selector, 0x1f)
                        index := byte(suffix, 0x00001b0000001e00000000000000000000000000000000001f1c1d0000001a00)
                    }

                    // Extract the selector at the expected index, where 0x2af25238b9aaf526d2a8169ace40d339ac049de28778391e
                    // is simply the selectors concatenated.
                    let expected_selector
                    {
                        let shift := byte(index, 0x20406080a0)
                        expected_selector := shr(shift, 0x2af25238b9aaf526d2a8169ace40d339ac049de28778391e)
                        expected_selector := and(expected_selector, 0xffffffff)
                    }

                    // Check if the `selector` matches the `expected_selector`
                    let valid := eq(selector, expected_selector)

                    // Validate the calldatasize against the minimal size
                    {
                        let min_calldata_size := byte(index, 0x838363634343)
                        valid := and(valid, gt(calldatasize(), min_calldata_size))
                        mstore(0x00, sub(min_calldata_size, 4))
                    }

                    // Revert if the selector is invalid
                    if iszero(valid) { revert(0, 0) }

                    ///////////////////////////////
                    // Load the previous context //
                    ///////////////////////////////
                    // First try to retrieve the context using EIP-1153 TRANSIENT STORAGE, the result is automatically
                    // stored in corresponding static memory.
                    // Obs: This call use all 2000 gas if the EVM doesn't support EIP-1153, and 472 gas if it supports.
                    // We provide an extra gas margin in case those opcodes change their gas cost in the future.
                    let support_eip1153 := staticcall(2000, address(), 0, 0, 0x0180, 0x80)

                    // if it doesn't support EIP-1153, then load the previous context from storage.
                    if iszero(support_eip1153) {
                        let slot0 := sload(0)
                        if xor(slot0, not(0)) {
                            mstore(0x0180, slot0)
                            mstore(0x01a0, sload(1))
                            mstore(0x01c0, sload(2))

                            // Only load the value if the `HAS_VALUE` flag is set.
                            // This flag is used to avoid storing a non-zero value in the storage.
                            let has_value := and(slot0, 0x01)
                            if has_value { mstore(0x01e0, sload(3)) }
                        }
                    }

                    // Set the bitflags using byte lookup.
                    //   HAS_ARGUMENTS = 0x01
                    //    HAS_CALLBACK = 0x02
                    //      IS_CREATE3 = 0x04
                    // SUPPORT_EIP1153 = 0x08
                    bitflags := or(shl(3, support_eip1153), byte(index, 0x030701050004))
                }

                let valid
                /////////////////////////////
                // Validate `creationCode` //
                /////////////////////////////
                let min_calldata_size := mload(0x00)
                {
                    // creationcode_ptr <= 0xffffffffffffffff
                    let creationcode_ptr := calldataload(0x24)
                    valid := lt(creationcode_ptr, 0x010000000000000000)
                    // creationcode_ptr > min_calldata_size
                    valid := and(valid, gt(creationcode_ptr, min_calldata_size))

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

                    // store the `creationcode_ptr` and `creationcode_len` at static memory 0xc0-0xe0
                    mstore(0xc0, creationcode_ptr)
                    mstore(0xe0, creationcode_len)
                }

                //////////////////////////
                // Validate `arguments` //
                //////////////////////////
                {
                    // args_ptr <= 0xffffffffffffffff
                    let args_ptr := calldataload(0x44)
                    let has_args := and(bitflags, 0x01)
                    let valid_args := and(has_args, lt(args_ptr, 0x010000000000000000))
                    // args_ptr > min_calldata_size
                    valid_args := and(valid_args, gt(args_ptr, min_calldata_size))

                    // calldatasize > (args_ptr + 0x1f)
                    args_ptr := add(args_ptr, 0x04)
                    valid_args := and(valid_args, slt(add(args_ptr, 0x1f), calldatasize()))

                    // args_len <= 0x3fffff
                    let args_len := calldataload(args_ptr)
                    valid_args := and(valid_args, lt(args_len, 0x400000))
                    args_ptr := add(args_ptr, 0x20)

                    // (args_ptr + args_len + 0x20) >= calldatasize
                    valid_args := and(valid_args, iszero(gt(add(args_ptr, args_len), calldatasize())))

                    // Set args_ptr and args_len to zero if there's no arguments
                    valid_args := and(valid_args, has_args)
                    args_ptr := mul(args_ptr, valid_args)
                    args_len := mul(args_len, valid_args)

                    // store the `args_ptr` and `args_len` at static memory 0x0100-0x0120
                    mstore(0x0100, args_ptr)
                    mstore(0x0120, args_len)

                    // If has no arguments, it is always valid.
                    valid := and(valid, or(valid_args, iszero(has_args)))
                }

                /////////////////////////
                // Validate `callback` //
                /////////////////////////
                {
                    // callback_ptr <= 0xffffffffffffffff
                    let callback_ptr := calldataload(0x64)
                    let valid_callback := lt(callback_ptr, 0x010000000000000000)
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

                    // Set callback_ptr and callback_len to zero if there's no callback
                    let has_callback := and(shr(1, bitflags), 1)
                    valid_callback := and(valid_callback, has_callback)
                    callback_ptr := mul(callback_ptr, valid_callback)
                    callback_len := mul(callback_len, valid_callback)

                    // store the `callback_ptr` and `callback_len` at static memory 0x0140-0x0160
                    mstore(0x0140, callback_ptr)
                    mstore(0x0160, callback_len)

                    // If the call has no callback, it is always valid.
                    valid_callback := or(valid_callback, iszero(has_callback))
                    valid := and(valid, valid_callback)
                }

                if iszero(valid) { revert(0, 0) }
            }

            ///////////////////////////////////////////////////
            // Check if the maximum depth of 127 was reached //
            ///////////////////////////////////////////////////
            {
                // Decode the previous `depth`.
                let slot0 := mload(0x0180)
                let depth := and(shr(3, slot0), 0x7f)

                // The `depth` must be less than 127, which is the maximum number of nested calls before overflow.
                // obs: probably impossible to reach this limit, due EIP-150 `all but one 64th`.
                // - reference: https://eips.ethereum.org/EIPS/eip-150
                if gt(depth, 0x7e) {
                    // revert CallStackOverflow()
                    mstore(0x00, 0x41f739de)
                    revert(0x1c, 0x04)
                }

                mstore(0xa0, add(depth, 1))
            }

            // Workaround for Frontier EVM chains, where `address(this).balance` can be less than `msg.value` if
            // this contract has no previous existential deposit.
            // - https://github.com/polkadot-evm/frontier/blob/polkadot-v1.11.0/ts-tests/tests/test-balance.ts#L41
            //
            // The following code is a branchless version of the ternary operator, equivalent to:
            // ```solidity
            // uint256 value = address(this).balance < msg.value ? address(this).balance : msg.value;
            // ```
            // also see: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/4976
            let value := xor(callvalue(), mul(xor(selfbalance(), callvalue()), lt(selfbalance(), callvalue())))

            ////////////////////////////
            // Compute Arguments Hash //
            ////////////////////////////
            {
                let arguments_ptr := mload(0x0100)
                let arguments_len := mload(0x0120)
                // Copy `arguments` to memory
                calldatacopy(0x0200, arguments_ptr, arguments_len)

                // Compute the keccak256 hash of the `arguments`
                let arguments_hash := keccak256(0x0200, arguments_len)

                // Set zero if there's no `arguments`.
                arguments_hash := mul(arguments_hash, gt(arguments_ptr, 0))

                // Save the `arguments_hash` in the static memory
                mstore(0x60, arguments_hash)
            }

            {
                let addr
                {
                    // Copy `creationCode` to memory
                    let creationcode_len := mload(0xe0)
                    {
                        let creationcode_ptr := mload(0xc0)
                        calldatacopy(0x0200, creationcode_ptr, creationcode_len)
                    }

                    ////////////////////////////////////////////////////////////////////
                    //                      Compute CREATE2 address                   //
                    ////////////////////////////////////////////////////////////////////
                    addr := or(address(), 0xff0000000000000000000000000000000000000000)
                    mstore(0x00, addr)
                    mstore(0x20, calldataload(0x04))
                    let creationcode_hash := keccak256(0x0200, creationcode_len)
                    mstore(0x40, creationcode_hash)
                    let create2_addr := and(keccak256(11, 85), 0xffffffffffffffffffffffffffffffffffffffff)

                    ////////////////////////////////////////////////////////////////////
                    //                      Compute CREATE3 address                   //
                    ////////////////////////////////////////////////////////////////////
                    // Compute `CREATE3` salt, which is `keccak25(abi.encodePacked(msg.sender, salt))`
                    mstore(0x00, caller())
                    mstore(0x20, calldataload(0x04))
                    mstore(0x20, keccak256(12, 52))

                    // Compute `CREATE3` proxy address, which is `keccak256(abi.encodePacked(0xff, address(this), create3salt, proxyHash))`
                    mstore(0x00, addr)
                    let proxy_hash := 0x0281a97663cf81306691f0800b13a91c4d335e1d772539f127389adae654ffc6

                    mstore(0x40, proxy_hash)
                    let proxy_addr := and(keccak256(11, 85), 0xffffffffffffffffffffffffffffffffffffffff)

                    // Compute `CREATE3` contract address, which is `keccak256(abi.encodePacked(hex"d694", proxyAddr, hex"01"))`
                    mstore(0x00, or(0xd694000000000000000000000000000000000000000001, shl(8, proxy_addr)))
                    let create3_addr := and(keccak256(0x09, 23), 0xffffffffffffffffffffffffffffffffffffffff)

                    //////////////////////
                    //     Validate     //
                    //////////////////////

                    // Validate if the contract exists and if the `creationCode` is not the `Create3Proxy` contract.
                    //
                    // IMPORTANT: The `Create3Proxy` creationCode CANNOT be used in `create2(...)` functions, otherwise
                    // anyone can deploy an contract in a address that belongs to another `msg.sender`.
                    // If someone attempt it, this contract reverts with `ReservedInitCode` error.
                    {
                        let is_create3 := and(shr(2, bitflags), 1)
                        addr := xor(create2_addr, mul(xor(create3_addr, create2_addr), is_create3))

                        // The proxy creation code is reserved only for `create3` methods
                        let invalid_init_code := and(eq(creationcode_hash, proxy_hash), iszero(is_create3))
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

                    // Store final contract address, proxy address and creationCode in
                    // their respective static memory slots.
                    mstore(0x00, addr)
                    mstore(0x20, proxy_addr)
                    mstore(0x40, creationcode_hash)
                }

                ////////////////////////////////////////////////////////////////////
                //                           UPDATE CONTEXT                       //
                ////////////////////////////////////////////////////////////////////

                //                       Context Storage Layout
                // | 32-bit |  22-bit  |   32-bit   |  160-bit   |  7-bit  | 3-bit |
                // +-+-+-+-+-+-+-+-+-+-+-+--+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+
                // |  args  | args len |  selector  |  contract  |  depth  | flags | offset: 0
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |   args[..12] (96-bit)  |           sender (160-bit)           | offset: 1
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                             salt                              | offset: 2
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                             value                             | offset: 3
                // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
                // |                       keccak256(args)*                        | offset: 2**64 * depth
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                          args[16..]                           | offset: 2**64 * depth + 1
                // |                             ...                               | length: (args.length + 15) / 32
                // +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

                let arguments_ptr := mload(0x0100)
                let arguments_len := mload(0x0120)
                let arguments_data := mul(calldataload(arguments_ptr), gt(arguments_ptr, 0))

                let slot0
                // Encode `args[12..16]` (32 bits)
                {
                    let has_args := and(bitflags, 0x01)
                    let args := shr(224, shl(96, arguments_data))
                    args := mul(args, has_args)
                    slot0 := args
                }
                // Encode args_len (22 bits)
                // Obs: validated previously, so is always less than 2**22
                slot0 := or(shl(22, slot0), arguments_len)
                // Encode selector (32 bits)
                {
                    let callback_ptr := mload(0x0140)
                    let callback_len := mload(0x0160)
                    let callback_selector := shr(224, calldataload(callback_ptr))
                    callback_selector := mul(callback_selector, gt(callback_len, 0))
                    slot0 := or(shl(32, slot0), callback_selector)
                }
                // Encode contractAddress (160 bits)
                slot0 := or(shl(160, slot0), addr)
                // Encode depth (7 bits)
                let depth := mload(0xa0)
                slot0 := or(shl(7, slot0), depth)
                // Encode bitflags (3 bits)
                slot0 := or(shl(3, slot0), or(and(bitflags, 0x06), gt(value, 0)))

                // Encode `args[..12]` (96 bit) + sender (160 bit)
                let slot1 := or(shl(160, shr(160, arguments_data)), caller())
                // Encode salt (256 bits)
                let salt := calldataload(0x04)

                // Store the new Context in the transient storage or storage.
                let support_eip1153 := and(bitflags, 0x08)
                switch support_eip1153
                case 0 {
                    // Store the context in the storage, skip `value` if zero.
                    sstore(0, slot0)
                    sstore(1, slot1)

                    // Once the `salt` zero is very common, we XOR it with the slot0 to reduce the likelihood
                    // of storing a zero value, otherwise using the salt zero ended up using more gas than
                    // using a non-zero salt, which is inconvenient but not an issue at all.
                    // Notice the previous salt is always restored at the end of the execution. So this value
                    // cannot influence any subsequent contract creation gas cost.
                    sstore(2, xor(salt, slot0))

                    // When `msg.value > 0`, then the first bit of `flags` is set, so no need to store this value (saves ~2900 gas).
                    if value { sstore(3, value) }
                    if gt(arguments_len, 16) {
                        // When `arguments.length > 16`, we also store the argument hash in the context.
                        let arguments_hash := mload(0x60)

                        /// If `args.length > 16`, then store the remaining bytes in the transient storage,
                        // starting at index `2**64 * depth`.
                        for {
                            let end := add(arguments_ptr, arguments_len)
                            let ptr := add(arguments_ptr, 16)
                            let offset := shl(64, depth)
                            sstore(offset, arguments_hash)
                            offset := add(offset, 0x01)
                        } lt(ptr, end) {
                            ptr := add(ptr, 0x20)
                            offset := add(offset, 0x01)
                        } { sstore(offset, xor(calldataload(ptr), arguments_hash)) }
                    }
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
                        let end := add(arguments_ptr, arguments_len)
                        let ptr := add(arguments_ptr, 16)
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
                let creationcode_len := mload(0xe0)
                let contract_addr :=
                    create2(mul(value, iszero(and(bitflags, 0x06))), 0x0200, creationcode_len, calldataload(0x04))

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
                // 0x763318602e57363d3d37363d47f080915215602e57f35bfd602b52336014526460203d3d733d526030601bf3:
                //     0x00  0x763318602e..  PUSH23 0x3318.. 0x3318602e57363d3d37363d47f080915215602e57f35bfd
                //     0x18  0x602b          PUSH1 0x2b      43 0x3318602e57363d3d37363d47f080915215602e57f35bfd
                //     0x1a  0x52            MSTORE
                //     0x1b  0x33            CALLER          addr
                //     0x1c  0x6014          PUSH1 20        20 addr
                //     0x1f  0x52            MSTORE
                //     0x25  0x6460203d3d73  PUSH5 0x6020..  0x60203d3d73
                //     0x26  0x3d            RETURNDATASIZE  0 0x60203d3d73
                //     0x27  0x52            MSTORE
                //     0x29  0x6030          PUSH1 48        48
                //     0x2a  0x601b          PUSH1 27        27 48
                //     0x2b  0xf3            RETURN

                // Create3Proxy runtime code, where `XXXX..` is the Universal Factory contract address.
                // 0x60203d3d73XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX3318602e57363d3d37363d47f080915215602e57f35bfd
                //     0x00  0x6020          PUSH1 32        32
                //     0x02  0x3d            RETURNDATASIZE  0 32
                //     0x03  0x3d            RETURNDATASIZE  0 0 32
                //     0x04  0x74XXXXXX..    PUSH20 XXXXXXX  factory 0 0 32
                //     0x19  0x33            CALLER          caller factory 0 0 32
                //     0x1a  0x18            XOR             invalid 0 0 32
                //     0x1b  0x602e          PUSH1 0x2e      46 invalid 0 0 32
                // ,=< 0x1d  0x57            JUMPI           0 0 32
                // |   0x1e  0x36            CALLDATASIZE    cls 0 0 32
                // |   0x1f  0x3d            RETURNDATASIZE  0 cls 0 0 32
                // |   0x20  0x3d            RETURNDATASIZE  0 0 cls 0 0 32
                // |   0x21  0x37            CALLDATACOPY    0 0 32
                // |   0x22  0x36            CALLDATASIZE    cls 0 0 32
                // |   0x23  0x3d            RETURNDATASIZE  0 cls 0 0 32
                // |   0x24  0x47            SELFBALANCE     val 0 cls 0 0 32
                // |   0x25  0xf0            CREATE          addr 0 0 32
                // |   0x26  0x80            DUP1            addr addr 0 0 32
                // |   0x27  0x91            SWAP2           0 addr addr 0 32
                // |   0x28  0x52            MSTORE          addr 0 32
                // |   0x29  0x16            ISZERO          fail 0 32
                // |   0x2a  0x602e          PUSH1 0x2e      46 fail 0 32
                // |=< 0x2c  0x57            JUMPI           0 32
                // |   0x2d  0xf3            RETURN
                // `=> 0x2e  0x5b            JUMPDEST
                //     0x2f  0xfd            REVERT

                // Deploy the `Create3Proxy`
                let proxy_addr
                {
                    // Save the current memory state, to restore it after the proxy deployment.
                    let mem00 := mload(0x00)
                    let mem20 := mload(0x20)
                    {
                        // Compute `CREATE3` salt, which is `keccak25(abi.encodePacked(msg.sender, salt))`
                        mstore(0x00, caller())
                        mstore(0x20, calldataload(0x04))
                        let salt := keccak256(12, 52)

                        // Store `Create3Proxy` initcode in memory.
                        mstore(0x0c, 0x60203d3d733d526030601bf3)
                        mstore(0x00, 0x763318602e57363d3d37363d47f080915215602e57f35bfd602b523360145264)
                        proxy_addr := create2(0, 0x00, 44, salt)
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
                let creationcode_len := mload(0xe0)

                // Only send funds if there's no callback
                let no_callback := iszero(and(bitflags, 0x02))

                // Deploy the contract using `Create3Proxy`
                let success := call(gas(), proxy_addr, mul(value, no_callback), 0x0200, creationcode_len, 0x00, 0x20)

                // Compare the computed address and actual address
                if or(iszero(success), xor(computed_addr, mload(0))) {
                    // 0x08fde50a -> Create3Failed()
                    mstore(0x00, 0x08fde50a)
                    revert(0x1c, 0x04)
                }
            }

            // Emit `ContractCreated` event and call `callback` if provided
            {
                let callback_ptr := mload(0x140)
                let callback_len := mload(0x160)
                {
                    // Compute `keccak256(callback)`
                    let callback_hash

                    // Copy `callback` to memory
                    calldatacopy(0x0200, callback_ptr, callback_len)

                    // Compute callback hash
                    callback_hash := keccak256(0x0200, callback_len)

                    // Set zero if there's no callback
                    callback_hash := mul(callback_hash, gt(callback_ptr, 0))

                    // emit ContractCreated(contractAddress, creationCodeHash, salt, dataHash, codeHash, callbackHash, depth, value)
                    let creation_code_hash := mload(0x40)
                    let contract_addr := mload(0)
                    let args_hash := mload(0x60)
                    let depth := mload(0xa0)
                    mstore(0x20, args_hash)
                    mstore(0x40, extcodehash(contract_addr))
                    mstore(0x60, callback_hash)
                    mstore(0x80, depth)
                    mstore(0xa0, value)
                    log4(0x20, 0xa0, contract_addr, creation_code_hash, calldataload(0x04), caller())

                    // Restore contract addr
                    mstore(0, contract_addr)
                }

                // Call `callback` if provided
                if callback_ptr {
                    if iszero(call(gas(), mload(0), value, 0x0200, callback_len, 0, 0)) {
                        mstore(0x00, 0x30b9b6dd)
                        // error offset
                        mstore(0x20, 0x20)
                        // error length
                        mstore(0x40, returndatasize())
                        // cleanup padding bytes, in case it has non-zero bytes
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
            let prev_slot0 := mload(0x0180)
            let prev_slot1 := mload(0x01a0)
            let prev_salt := mload(0x01c0)
            let prev_value := mload(0x01e0)
            let support_eip1153 := and(bitflags, 0x08)
            switch support_eip1153
            case 0 {
                let is_empty := iszero(prev_slot0)
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
