// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

// import {VmSafe} from "forge-std/Vm.sol";
import {Test, console} from "forge-std/Test.sol";
import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";
import {SingletonFactory} from "../../src/SingletonFactory.sol";

contract MockContract {
    // VmSafe internal constant VM = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    ISingletonFactory private immutable FACTORY;
    uint256 public immutable NONCE;

    constructor(ISingletonFactory factory, address owner) {
        // {
        //     (bool success, bytes memory data) = address(factory).call(hex"deadbeef");
        //     require(success, "call failed");
        //     (bytes32 a, bytes32 b, bytes32 c, bytes32 d) = abi.decode(data, (bytes32, bytes32, bytes32, bytes32));
        //     require((a | b | c) != bytes32(0), "invalid data, empty");

        //     string memory ctx0 = VM.toString(a);
        //     string memory ctx1 = VM.toString(b);
        //     string memory ctx2 = VM.toString(c);
        //     string memory temp = VM.toString(d);
        //     console.log("         ctx0:", ctx0);
        //     console.log("         ctx1:", ctx1);
        //     console.log("         ctx2:", ctx2);
        //     console.log("         temp:", temp);

        //     (success, data) = address(factory).call(hex"d0496d6a");
        //     if (data.length > 0x1000) {
        //         assembly {
        //             mstore(data, 0x1000)
        //         }
        //     }
        //     console.logBytes(data);

        //     require(success, "call failed");
        //     require(data.length < 0x6000, "call failed");
        // }

        // bytes memory jose;
        // uint256 returnSizeJose;
        // bool success;
        // assembly {
        //     jose := mload(0x40)
        //     mstore(jose, shl(224, 0xd0496d6a))
        //     // mstore(jose, shl(224, 0xdeadbeef))
        //     success := staticcall(gas(), factory, jose, 4, 0, 0)
        //     returnSizeJose := returndatasize()
        //     mstore(jose, returndatasize())
        //     returndatacopy(add(jose, 0x20), 0, returndatasize())
        //     mstore(0x40, and(add(mload(0x40), add(0x3f, returndatasize())), 0xffffffffffffffe0))
        // }
        // console.log("      success:", success);
        // console.log("         size:", returnSizeJose);
        // console.logBytes(jose);

        // console.log("      factory:", address(factory));
        // console.log("        owner:", owner);
        // console.log("address(this):", address(this));
        // console.log("   msg.sender:", msg.sender);
        Context memory ctx = factory.context();
        // console.log("   ctx.sender:", ctx.sender);
        // console.log("    tx.origin:", tx.origin);
        require(ctx.contractAddress == address(this), "address mismatch");
        require(ctx.callDepth == 1, "depth mismatch");
        require(ctx.sender == owner, "unauthorized tx origin");
        require(ctx.hasCallback, "requires callback");
        require(ctx.callbackSelector == MockContract.initialize.selector, "invalid callback");
        NONCE = ctx.salt;
        FACTORY = factory;
    }

    function initialize() external payable {
        require(msg.sender == address(FACTORY), "unauthorized");
        require(msg.value > 0, "send money!!");
    }
}
