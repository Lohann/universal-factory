// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

// import {VmSafe} from "forge-std/Vm.sol";
// import {Test, console} from "forge-std/Test.sol";
import {ISingletonFactory, Context} from "../../src/ISingletonFactory.sol";
import {SingletonFactory} from "../../src/SingletonFactory.sol";

contract MockContract {
    // VmSafe internal constant VM = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    ISingletonFactory private immutable FACTORY;
    uint256 public immutable NONCE;

    constructor(ISingletonFactory factory, address owner) {
        // {
        //     string memory ctx0 = VM.toString(VM.load(address(factory), bytes32(uint256(0))));
        //     string memory ctx1 = VM.toString(VM.load(address(factory), bytes32(uint256(1))));
        //     string memory ctx2 = VM.toString(VM.load(address(factory), bytes32(uint256(2))));
        //     console.log("         ctx0:", ctx0);
        //     console.log("         ctx1:", ctx1);
        //     console.log("         ctx2:", ctx2);

        //     string memory temp = VM.toString(VM.load(address(factory), bytes32(uint256(500))));
        //     console.log("         temp:", temp);
        // }
        Context memory ctx = factory.context();
        // console.log("address(this):", address(this));
        // console.log("        owner:", owner);
        // console.log("   ctx.sender:", ctx.sender);
        // console.log("   msg.sender:", msg.sender);
        // console.log("    tx.origin:", tx.origin);
        require(ctx.contractAddress == address(this), "address mismatch");
        require(ctx.callDepth == 0, "depth mismatch");
        require(ctx.sender == owner, "unauthorized tx origin");
        require(ctx.hasInitializer, "requires initializer");
        require(ctx.initializer.length == 4, "invalid initializer");
        bytes memory slice = ctx.initializer;
        bytes4 selector;
        assembly {
            selector := mload(add(slice, 0x20))
        }
        require(selector == MockContract.initialize.selector, "invalid selector");
        NONCE = ctx.salt;
        FACTORY = factory;
    }

    function initialize() external payable {
        require(msg.sender == address(FACTORY), "unauthorized");
        require(msg.value > 0, "send money!!");
    }
}
