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

                // `function context() external view returns (Context memory)`
                if eq(selector, 0xd0496d6a) {
                    if callvalue() { revert(0, 0) }
                    let ctx0 := tload(0)
                    let ctx1 := tload(1)
                    let salt := tload(2)

                    // Parse context
                    let initializer_len := and(shr(8, ctx0), 0xffffffff)
                    let initializer_val := and(shr(40, ctx0), 0xffffffffffffffffffffffffffffffffffffff)

                    // An empty initializer is encoded encoded as zero `initializer_len` and non-zero `initializer_val`.
                    let has_initializer := or(eq(initializer_val, iszero(initializer_len)), gt(initializer_len, 0))
                    initializer_val := mul(initializer_val, gt(initializer_len, 0))

                    // Build Context in memory
                    mstore(0x0000, 0x20) // offset
                    mstore(0x0020, and(ctx1, 0xffffffffffffffffffffffffffffffffffffffff)) // contract_address
                    mstore(0x0040, or(shl(96, shr(192, ctx0)), shr(160, ctx1))) // caller
                    mstore(0x0060, salt) // salt
                    mstore(0x0080, and(ctx0, 0xff)) // call depth
                    mstore(0x00a0, has_initializer) // call with initializer
                    mstore(0x00c0, initializer_len) // initializer_len
                    mstore(0x00e0, 0xe0) // offset
                    mstore(0x0100, xor(19, mul(xor(initializer_len, 19), lt(initializer_len, 19)))) // min(initializer_len, 19)
                    mstore(0x0120, shl(104, initializer_val)) // initializer_val
                    return(0x00, add(0x0120, shl(5, gt(initializer_len, 0))))
                }

                // Check if it is CREATE3 method
                // - function create3(uint256 salt, bytes calldata creationCode)
                // - function create3(uint256 salt, bytes calldata creationCode, bytes calldata initializer)
                let is_create3 := or(eq(selector, 0x53ca4842), eq(selector, 0xb5164ce9))

                // Check seletor and minimal calldatasize when no initializer is provided
                // - function create2(uint256 salt, bytes calldata creationCode)
                valid := and(eq(selector, xor(0xfe984079, mul(0xad52083b, is_create3))), gt(calldatasize(), 0x43))

                // Check seletor and minimal calldatasize when an initializer is provided
                // - function create2(uint256 salt, bytes calldata creationCode, bytes calldata initializer)
                let has_initializer := eq(selector, xor(0x579da0bf, mul(0xe28bec56, is_create3)))
                valid := or(valid, and(has_initializer, gt(calldatasize(), 0x63)))

                // Set `deploy_proxy` and `has_initializer` flags
                flags := or(shl(1, is_create3), has_initializer)
            }

            let initializer_ptr
            let initializer_len
            {
                // initializer_ptr <= 0xffffffffffffffff
                initializer_ptr := calldataload(0x44)
                let valid_initializer := and(flags, lt(initializer_ptr, 0x010000000000000000))
                // initializer_ptr >= 0x5f
                valid_initializer := and(valid_initializer, gt(initializer_ptr, 0x5f))

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
                    let has_initializer := and(flags, 0x01)
                    // Set initializer_ptr and initializer_len to zero if there's no initializer
                    valid_initializer := and(valid_initializer, has_initializer)
                    initializer_ptr := mul(initializer_ptr, valid_initializer)
                    initializer_len := mul(initializer_len, valid_initializer)

                    // If the call has no initializer, it is always valid.
                    valid_initializer := or(valid_initializer, iszero(has_initializer))
                }
                valid := and(valid, valid_initializer)
            }

            // creationcode_ptr <= 0xffffffffffffffff
            let creationcode_ptr := calldataload(0x24)
            valid := and(valid, lt(creationcode_ptr, 0x010000000000000000))
            // creationcode_ptr >= 0x3f
            valid := and(valid, gt(creationcode_ptr, add(0x3f, shl(5, and(flags, 0x01)))))

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
                let is_empty := sub(0, iszero(or(or(prev_ctx0, prev_ctx1), prev_salt)))
                prev_ctx0 := or(prev_ctx0, is_empty)
                prev_ctx1 := or(prev_ctx1, is_empty)
                prev_salt := or(prev_salt, is_empty)
            }

            {
                // Compute the new Context
                let depth := add(signextend(0, prev_ctx0), 1)
                {
                    // Decode previous `contractAddress` and `sender`.
                    let addr := and(prev_ctx1, 0xffffffffffffffffffffffffffffffffffffffff)
                    let sender := or(shl(96, shr(192, prev_ctx0)), shr(160, prev_ctx1))

                    // Decode previous `initializer`, calls without initializer are encoded as zero bytes and zero length.
                    let prev_initializer_len := and(shr(8, prev_ctx0), 0xffffffff)
                    let prev_initializer_val := and(shr(40, prev_ctx0), 0xffffffffffffffffffffffffffffffffffffff)
                    // An empty initializer is encoded encoded as zero `initializer_len` and non-zero `initializer_val`.
                    let prev_has_initializer :=
                        or(eq(prev_initializer_val, iszero(prev_initializer_len)), gt(prev_initializer_len, 0))

                    // Validate previous context
                    valid := eq(and(and(prev_ctx0, prev_ctx1), prev_salt), not(0))
                    // If any previous address exists, it must have been created by this contract.
                    valid := or(valid, iszero(or(eq(addr, 0xffffffffffffffffffffffffffffffffffffffff), iszero(addr))))
                    // Cannot do more than 127 nested calls, probably impossible due `EIP-150`.
                    valid := and(valid, lt(depth, 0x7f))
                    // Empty initializer MUST be encoded as `initializer_val = 1` and `initializer_len = 0`
                    valid := and(valid, iszero(and(gt(prev_initializer_val, 0x01), iszero(prev_initializer_len))))

                    if iszero(valid) {
                        // revert PreviousContextInvalid(addr, sender, salt, depth, has_initializer, init_len, init_bytes)
                        mstore(0x00, 0x69fa8359)
                        mstore(0x20, addr) // contract
                        mstore(0x40, sender) // sender
                        mstore(0x60, prev_salt) // salt
                        mstore(0x80, and(prev_ctx0, 0xff)) // depth
                        mstore(0x80, prev_has_initializer) // has initializer
                        mstore(0xc0, prev_initializer_len) // initializer len
                        mstore(0xe0, prev_initializer_val) // initializer val
                        revert(0x1c, 0x104)
                    }
                }

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
                let is_create3 := shr(1, flags)
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
                // Encode bytes19(initializer_ptr)
                let has_initializer := and(flags, 0x01)
                let ctx := mul(shr(104, calldataload(initializer_ptr)), has_initializer)
                ctx := or(ctx, gt(has_initializer, initializer_len))
                ctx := shl(40, ctx)
                // Encode caller high bits
                ctx := or(ctx, shl(192, shr(96, caller())))
                // Encode initializer_len
                ctx := or(ctx, shl(8, initializer_len))
                // Encode Depth
                tstore(0, or(ctx, depth))
                // Encode caller low bits + contract addr
                tstore(1, or(shl(160, caller()), addr))
                // Encode salt
                tstore(2, calldataload(0x04))
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
                let is_create3 := shr(1, flags)
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
                            mul(value, eq(flags, 0x02)), // Check if the flag HAS_INITIALIZER is disabled
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
                let is_create3 := shr(1, flags)
                mstore(0x00, xor(0x04a5b3ee, mul(0x0c5856e4, is_create3)))
                revert(0x1c, 0x04)
            }

            if and(flags, 0x01) {
                // copy callback to memory
                calldatacopy(0x80, initializer_ptr, initializer_len)

                // Call initializer
                if iszero(call(gas(), mload(0), value, 0x80, initializer_len, 0, 0)) {
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
            if and(eq(and(prev_ctx0, prev_ctx1), not(0)), gt(selfbalance(), 0)) {
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
