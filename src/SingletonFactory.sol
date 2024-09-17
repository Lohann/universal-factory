// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

contract SingletonFactory {
    constructor() {
        assembly {
            // If some balance is provided to this contract, refund the caller
            // As balance may be provided on substrate based chains as existential deposit,
            // in this case `selfbalance() < callvalue()`
            if selfbalance() {
                if iszero(call(gas(), caller(), selfbalance(), 0, 0, 0, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }
        }
    }

    fallback() external payable {
        assembly {
            // HAS_INITIALIZER_FLAG = 0x01
            //    DEPLOY_PROXY_FLAG = 0x02

            let flags := 0
            let valid
            {
                let selector := shr(0xe0, calldataload(0))

                if eq(selector, 0xdeadbeef) {
                    if callvalue() { revert(0, 0) }
                    mstore(0x00, tload(0))
                    mstore(0x20, tload(1))
                    mstore(0x40, tload(2))
                    mstore(0x60, tload(shl(64, 1)))
                    return(0x00, 0x80)
                }

                // `function context() external view returns (Context memory)`
                if eq(selector, 0xd0496d6a) {
                    if callvalue() { revert(0, 0) }
                    let ctx0 := tload(0)
                    let ctx1 := tload(1)
                    let salt := tload(2)

                    // if iszero(depth) {
                    //     mstore(0, 0xdeadbeefbabebabe)
                    //     revert(0, 0x20)
                    // }
                    // {
                    //     let has_context := gt(depth, 0)
                    //     ctx0 := mul(ctx0, has_context)
                    //     ctx1 := mul(ctx1, has_context)
                    //     salt := mul(salt, has_context)
                    // }

                    //                         Storage Layout
                    // | 32-bit |    160-bit   |  22-bit  | 2-bit |  32-bit  |  8-bit  |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |  data  |   contract   | data len | flags | selector |  depth  |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |       data      |                   sender                    |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |                             salt                              |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    // Decode `flags`.
                    //   IS_CREATE3 := 0x04
                    // HAS_CALLBACK := 0x02
                    //   HAS_PARAMS := 0x01
                    let depth := and(ctx0, 0xff)
                    let callback_selector := shl(224, shr(8, ctx0))
                    flags := and(shr(40, ctx0), 0x03)
                    let data_len := and(shr(42, ctx0), 0x3fffff)
                    let contract_addr := and(shr(64, ctx0), 0xffffffffffffffffffffffffffffffffffffffff)
                    let data := or(shl(160, shr(160, ctx1)), shl(128, shr(224, ctx0)))
                    let sender := and(ctx1, 0xffffffffffffffffffffffffffffffffffffffff)

                    // {
                    //     // only show the initializer if the caller is the contract itself
                    //     let is_caller := eq(contract_addr, caller())
                    //     data_len := mul(data_len, is_caller)
                    //     data := mul(data, is_caller)
                    // }

                    // Store `Context` in memory following Solidity ABI encoding
                    mstore(0x0000, 0x20) // offset
                    mstore(0x0020, contract_addr) // contract_address
                    mstore(0x0040, sender) // sender
                    mstore(0x0060, depth) // call depth
                    mstore(0x0080, shr(1, flags)) // kind (0 for CREATE2, 1 for CREATE3)
                    mstore(0x00a0, and(1, flags)) // hasCallback
                    mstore(0x00c0, callback_selector) // callbackSelector
                    mstore(0x00e0, salt) // salt
                    mstore(0x0100, 0x0100) // offset
                    mstore(0x0120, data_len) // data_len
                    mstore(0x0140, data) // initializer_val

                    // return(0x00, 0x0200)

                    // If `data.length > 16`, copy the remaining data to memory
                    for {
                        let end := add(0x0140, data_len)
                        let ptr := 0x150
                        let offset := shl(64, depth)
                    } lt(ptr, end) {
                        ptr := add(ptr, 0x20)
                        offset := add(offset, 0x01)
                    } { mstore(ptr, tload(offset)) }

                    // return(0x00, 0x160)
                    return(0x00, add(0x0140, and(add(data_len, 0x1f), 0xffffffffffffffe0)))
                }

                // Check if it is CREATE3 method
                // - function create3(uint256 salt, bytes calldata creationCode)
                // - function create3(uint256 salt, bytes calldata creationCode, bytes calldata data)
                // - function create3(uint256 salt, bytes calldata creationCode, bytes calldata data, bytes calldata callback)
                // let is_create3 := or(or(eq(selector, 0x53ca4842), eq(selector, 0xb5164ce9)), eq(selector, 0x1f7a56c0))

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
                flags := is_create3
                flags := or(shl(1, flags), has_callback)
                flags := or(shl(1, flags), has_data)
            }

            let initializer_ptr
            let initializer_len
            {
                // initializer_ptr <= 0xffffffffffffffff
                initializer_ptr := calldataload(0x44)
                let has_data := and(flags, 0x01)
                let valid_initializer := and(has_data, lt(initializer_ptr, 0x010000000000000000))
                // initializer_ptr > (has_callback ? 0x7f : 0x5f)
                {
                    let has_callback := shl(4, and(flags, 0x02))
                    valid_initializer := and(valid_initializer, gt(initializer_ptr, add(has_callback, 0x5f)))
                }

                // calldatasize > (initializer_ptr + 0x1f)
                initializer_ptr := add(initializer_ptr, 0x04)
                valid_initializer := and(valid_initializer, slt(add(initializer_ptr, 0x1f), calldatasize()))

                // initializer_len <= 0xffffffff
                initializer_len := calldataload(initializer_ptr)
                valid_initializer := and(valid_initializer, lt(initializer_len, 0x0100000000))
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
                let has_callback := and(shr(1, flags), 1)
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
                let data_and_callback := and(flags, 0x03)
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
            let prev_ctx0 := tload(0)
            let prev_ctx1 := tload(1)
            let prev_salt := tload(2)
            {
                // Compute the new Context
                let depth := and(prev_ctx0, 0xff)
                {
                    let first_call := iszero(or(prev_ctx0, or(prev_ctx1, prev_salt)))
                    {
                        // Decode previous `contractAddress`.
                        let contract_addr := shr(64, prev_ctx0)
                        // If this is not the first call, then `contractAddress` be non-zero, once is impossible
                        // to create an contract with address zero.
                        valid := or(gt(contract_addr, 0), first_call)
                    }

                    {
                        // Decode `data_len`.
                        let prev_data_len := and(shr(42, prev_ctx0), 0x3fffff)
                        // Decode first 20 bytes of `data[..20]`.
                        let prev_data := or(shr(160, prev_ctx1), shl(32, shr(224, prev_ctx0)))
                        // `prev_data` must fit in the `prev_data_len`
                        let limit := shl(shl(3, prev_data_len), 1)
                        limit := or(limit, shl(128, iszero(limit)))
                        valid := or(valid, lt(prev_data, limit))
                    }

                    // the `depth` must be less than 255, which is the maximum number of nested calls before overflow.
                    // obs: probably impossible to reach this limit, due EIP-150 `all but one 64th`.
                    valid := and(valid, lt(depth, 0xff))

                    if iszero(valid) {
                        // revert CallDepthOverflow()
                        mstore(0x00, 0xcc6c3e34)
                        revert(0x1c, 0x04)
                    }
                }
                depth := add(depth, 0x01)

                // Static Memory Layout:
                // 0x00        -> final contract address
                // 0x20        -> proxy contract address when using `create3`.
                // 0x40..<0x80 -> proxy creation code when using `create3`.
                // 0x80        -> memory offset of the provided creation code
                //
                // Obs: the memory layout above is ignored for revert messages, also can be
                // be used by a different purpose before it's final value is assigned.

                // Copy `creationCode` to memory
                calldatacopy(0x80, creationcode_ptr, creationcode_len)

                /////////////////////////////
                // Compute CREATE2 address //
                /////////////////////////////
                mstore(0x00, or(address(), 0xff0000000000000000000000000000000000000000))
                mstore(0x20, calldataload(0x04))
                // 0x9fc904680de2feb47c597aa19f58746c0a400d529ba7cfbe3cda504f5aa7914b == keccak256(proxyCreationCode)
                let creationcode_hash := keccak256(0x80, creationcode_len)
                let is_create3 := shr(2, flags)
                creationcode_hash :=
                    xor(
                        creationcode_hash,
                        mul(
                            xor(0x9fc904680de2feb47c597aa19f58746c0a400d529ba7cfbe3cda504f5aa7914b, creationcode_hash),
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
                            eq(creationcode_hash, 0x9fc904680de2feb47c597aa19f58746c0a400d529ba7cfbe3cda504f5aa7914b)
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

                /////////////////////////////
                // Compute CREATE3 address //
                /////////////////////////////
                mstore(0x40, or(0xd694000000000000000000000000000000000000000001, shl(8, addr)))
                let proxy_addr := and(keccak256(0x49, 23), 0xffffffffffffffffffffffffffffffffffffffff)

                // Select the final contract address
                addr := xor(addr, mul(xor(proxy_addr, addr), is_create3))

                // Store final contract address at 0x00
                mstore(0, addr)

                ////////////////////
                // UPDATE CONTEXT //
                ////////////////////
                //                         Storage Layout
                // | 32-bit |    160-bit   |  22-bit  | 2-bit |  32-bit  |  8-bit  |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |  data  |   contract   | data len | flags | selector |  depth  |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |       data      |                   sender                    |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                             salt                              |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                // Callback selector and depth (40 bits)

                let ctx
                // teste
                // Encode `data[96..128]` (32 bits)
                {
                    let has_data := and(flags, 0x01)
                    let data := shr(224, shl(96, calldataload(initializer_ptr)))
                    data := mul(data, has_data)
                    ctx := data
                }
                // Encode contractAddress (160 bits)
                ctx := or(shl(160, ctx), addr)
                // Encode data_len (22 bits)
                ctx := or(shl(22, ctx), initializer_len)
                // Encode flags (2 bits)
                ctx := or(shl(2, ctx), shr(1, flags))
                // Encode selector (32 bits)
                {
                    let callback_ptr := add(calldataload(0x64), 0x24)
                    let callback_selector := shr(224, calldataload(callback_ptr))
                    let has_callback := and(shr(1, flags), 1)
                    callback_selector := mul(callback_selector, has_callback)
                    ctx := or(shl(32, ctx), callback_selector)
                }
                // Encode depth (8 bits)
                ctx := or(shl(8, ctx), depth)
                // Store on the transient storage
                tstore(0, ctx)
                // Encode `data[..96]` (96 bit) + sender (160 bit)
                tstore(1, or(shl(160, shr(160, calldataload(initializer_ptr))), caller()))
                tstore(2, calldataload(0x04))

                // teste fim
                // // Encode depth (8 bits)
                // ctx := depth
                // // Encode selector (32 bits)
                // {
                //     let callback_ptr := add(calldataload(0x64), 0x24)
                //     let callback_selector := and(shr(217, calldataload(callback_ptr)), 0x7fffffff80)
                //     callback_selector := mul(callback_selector, and(flags, 0x02))
                //     ctx := or(ctx, callback_selector)
                // }
                // // Encode flags (2 bits)
                // ctx := or(ctx, shl(40, shr(1, flags)))
                // // Encode data_len (22 bits)
                // ctx := or(ctx, shl(42, initializer_len))
                // // Encode contractAddress (160 bits)
                // ctx := or(ctx, shl(64, addr))
                // // Encode `data[96..128]` (32 bits)
                // ctx := or(ctx, shl(224, shr(128, initializer_ptr)))
                // // Encode Depth
                // tstore(0, ctx)
                // Encode `data[..96]` (96 bit) + sender (160 bit)
                // ctx := shl(160, shr(160, initializer_ptr))
                // tstore(1, or(ctx, caller()))
                // Encode salt (256 bit)
                // tstore(2, calldataload(0x04))

                // Store `data` in the transient storage
                for {
                    let end := add(initializer_ptr, initializer_len)
                    let ptr := add(initializer_ptr, 16)
                    let offset := shl(64, depth)
                } lt(ptr, end) {
                    ptr := add(ptr, 0x20)
                    offset := add(offset, 0x01)
                } { tstore(offset, calldataload(ptr)) }
            }

            // Workaround for substrate evm based chains, where `selfbalance` can be less than
            // `callvalue` if this contract has no existential deposit.
            //
            // The following code is a branchless version of the ternary operator, equivalent to:
            // address(this).balance < msg.value ? address(this).balance : msg.value
            let value := xor(callvalue(), mul(xor(selfbalance(), callvalue()), lt(selfbalance(), callvalue())))

            // Create contract
            {
                // Store proxy bytecode in the static memory addresses 0x40 and 0x60
                mstore(0x40, 0x3360581b3d5260733d536022601560153960373df333143d3611166021573d3d)
                mstore(0x60, 0xfd5b60203d3d363d3d37363d34f080603357fd5b9052f3000000000000000000)

                // If `create3` is enabled, use the proxy creation code, otherwise use provided `creationCode`
                let is_create3 := shr(2, flags)
                let offset := shr(is_create3, 0x80)
                let length := xor(creationcode_len, mul(xor(55, creationcode_len), is_create3))

                // Deploy contract or Proxy, depending if `is_create3` is enabled.
                valid := create2(mul(value, iszero(flags)), offset, length, calldataload(0x04))

                if is_create3 {
                    // return an error if failed to create the proxy contract
                    if iszero(and(eq(valid, mload(0x20)), eq(extcodesize(valid), length))) {
                        // revert Create2Failed()
                        mstore(0x00, 0x04a5b3ee)
                        revert(0x1c, 0x04)
                    }

                    if iszero(
                        call(
                            gas(),
                            valid,
                            mul(value, iszero(and(flags, 0x02))), // Check if the flag HAS_CALLBACK is disabled
                            0x80,
                            creationcode_len,
                            0x20,
                            0x20
                        )
                    ) {
                        // revert Create3Failed()
                        mstore(0x00, 0x08fde50a)
                        revert(0x1c, 0x04)
                    }
                    valid := mload(0x20)
                }
            }

            // Computed address and actual address must match
            valid := eq(valid, mload(0))

            // The deployed contract cannot be empty
            valid := and(valid, gt(extcodesize(mload(0)), 0))

            // return an error if failed to create the contract
            if iszero(valid) {
                // 0x04a5b3ee -> Create2Failed()
                // 0x08fde50a -> Create3Failed()
                // 0x0c5856e4 -> 0x04a5b3ee ^ 0x08fde50a
                let is_create3 := shr(2, flags)
                mstore(0x00, xor(0x04a5b3ee, mul(0x0c5856e4, is_create3)))
                revert(0x1c, 0x04)
            }

            // Call `callback` if provided
            if and(flags, 0x02) {
                let callback_ptr := add(calldataload(0x64), 0x04)
                let callback_len := calldataload(callback_ptr)
                callback_ptr := add(callback_ptr, 0x20)

                // copy callback to memory
                calldatacopy(0x80, callback_ptr, callback_len)

                // Call initializer
                if iszero(call(gas(), mload(0), value, 0x80, callback_len, 0, 0)) {
                    mstore(0x00, 0xe47a66c8)
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

            // self balance must be zero at the end of execution
            // Once on substrate evm chains the `selfbalance() <= callvalue()` this make
            // sure there's no remaining balance left in this contract.
            if and(iszero(or(or(prev_ctx0, prev_ctx1), prev_salt)), gt(selfbalance(), 0)) {
                // revert InvalidSelfBalance(address(this).balance)
                mstore(0x00, 0xff9334bf)
                mstore(0x20, selfbalance())
                revert(0x1c, 0x24)
            }

            // Restore previous ctx and salt
            tstore(0, prev_ctx0)
            tstore(1, prev_ctx1)
            tstore(2, prev_salt)

            // return the created contract address
            return(0, 0x20)
        }
    }
}
