// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {UniversalFactory} from "@universal-factory/UniversalFactory.sol";
import {Context, IUniversalFactory} from "@universal-factory/IUniversalFactory.sol";
import {FactoryUtils} from "@universal-factory/FactoryUtils.sol";
import {Deployer} from "./Deployer.sol";
import {MyContract} from "./MyContract.sol";
import {TestUtils} from "../helpers/TestUtils.sol";

contract DeployerTest is Test {
    using FactoryUtils for IUniversalFactory;

    address internal constant FACTORY_DEPLOYER = 0x908064dE91a32edaC91393FEc3308E6624b85941;
    IUniversalFactory internal constant FACTORY = IUniversalFactory(
        address(uint160(uint256(keccak256(abi.encodePacked(uint16(0xd694), FACTORY_DEPLOYER, uint8(0x80))))))
    );

    constructor() {
        vm.deal(FACTORY_DEPLOYER, 100 ether);
        assertEq(vm.getNonce(FACTORY_DEPLOYER), 0);
        vm.prank(FACTORY_DEPLOYER, FACTORY_DEPLOYER);
        address factory = address(new UniversalFactory());
        assertEq(factory, address(FACTORY));
    }

    function test_deployer(bytes32 salt, uint256 privateKey) external {
        vm.assume(privateKey > 0 && privateKey < SECP256K1_ORDER);
        VmSafe.Wallet memory wallet = vm.createWallet(privateKey);
        // `Deployer` owner address
        address owner = wallet.addr;
        bytes memory deployerCreationCode = bytes.concat(type(Deployer).creationCode, abi.encode(owner));
        bytes memory myContractCreationCode = type(MyContract).creationCode;
        bytes memory callback = abi.encodeCall(Deployer.deploy, (type(MyContract).creationCode));
        bytes32 initCodeHash = keccak256(myContractCreationCode);

        // Pre-compute the reserved contract address.
        address deployerAddr = FACTORY.computeCreate2Address(salt, deployerCreationCode);
        address myContractAddr = FACTORY.computeCreateAddress(deployerAddr, 1);

        // Check if both contracts are not deployed.
        assertEq(deployerAddr.code.length, 0, "Deployer already exists");
        assertEq(myContractAddr.code.length, 0, "MyContract already exists");

        // Sign the digest.
        bytes32 digest = keccak256(abi.encodePacked(deployerAddr, initCodeHash, block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet, digest);
        bytes memory arguments = abi.encode(v, r, s, initCodeHash);

        // Check deploy with callback
        Deployer deployer = Deployer(FACTORY.create2(salt, deployerCreationCode, arguments, callback));

        // Check if both contracts are deployed.
        require(address(deployer) == deployerAddr, "deployer address mismatch");
        require(address(myContractAddr).code.length > 0, "MyContract not deployed");
    }
}
