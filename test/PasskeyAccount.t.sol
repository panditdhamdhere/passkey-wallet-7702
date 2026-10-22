// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {PasskeyAccount} from "../src/PasskeyAccount.sol";

contract Counter {
    uint256 public count;
    address public lastCaller;
    function bump() external payable { count++; lastCaller = msg.sender; }
}

contract PasskeyAccountTest is Test {
    uint256 constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    PasskeyAccount impl;
    Counter counter;

    uint256 alicePk = 0xA11CE;   // secp256k1 EOA key
    address alice;
    uint256 passkey = 0xBEEF;    // secp256r1 "passkey" (stands in for Secure Enclave)
    uint256 qx; uint256 qy;
    address relayer = makeAddr("relayer");

    function setUp() public {
        impl = new PasskeyAccount();
        counter = new Counter();
        alice = vm.addr(alicePk);
        (qx, qy) = vm.publicKeyP256(passkey);

        // EIP-7702: alice signs an authorization pointing her EOA at impl.
        Vm.SignedDelegation memory auth = vm.signDelegation(address(impl), alicePk);
        vm.attachDelegation(auth);
        // Next call is the "type 4" tx: alice calls herself to set the key.
        vm.prank(alice);
        PasskeyAccount(payable(alice)).initialize(qx, qy);
        vm.deal(alice, 1 ether);
    }

    function _sign(uint256 pk, address acct, address target, uint256 value, bytes memory data, uint256 n)
        internal view returns (bytes32 r, bytes32 s)
    {
        bytes32 h = PasskeyAccount(payable(acct)).digest(target, value, data, n);
        (r, s) = vm.signP256(pk, h);
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s)); // normalise to low-s
    }

    function test_DelegationIndicatorIsSet() public view {
        // 0xef0100 || impl  (23 bytes)
        assertEq(alice.code, abi.encodePacked(hex"ef0100", address(impl)));
        assertEq(PasskeyAccount(payable(alice)).qx(), qx);
    }

    function test_PrecompileDirect() public {
        bytes32 h = keccak256("hello passkey");
        (bytes32 r, bytes32 s) = vm.signP256(passkey, h);
        uint256 g = gasleft();
        (bool ok, bytes memory out) = address(0x100).staticcall(abi.encode(h, r, s, qx, qy));
        uint256 used = g - gasleft();
        assertTrue(ok);
        assertEq(abi.decode(out, (uint256)), 1);
        emit log_named_uint("gas around P256VERIFY staticcall", used);
        assertGe(used, 6900);

        // wrong message -> empty output, call still succeeds (precompile never reverts)
        (ok, out) = address(0x100).staticcall(abi.encode(keccak256("other"), r, s, qx, qy));
        assertTrue(ok);
        assertEq(out.length, 0);
    }

    function test_RelayerExecutesWithPasskey() public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        (bytes32 r, bytes32 s) = _sign(passkey, alice, address(counter), 0.1 ether, data, 0);
        vm.prank(relayer);
        PasskeyAccount(payable(alice)).execute(address(counter), 0.1 ether, data, r, s);
        assertEq(counter.count(), 1);
        assertEq(counter.lastCaller(), alice); // the call comes FROM alice's address
        assertEq(address(counter).balance, 0.1 ether);
        assertEq(PasskeyAccount(payable(alice)).nonce(), 1);
    }

    function test_ReplayFails() public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        (bytes32 r, bytes32 s) = _sign(passkey, alice, address(counter), 0, data, 0);
        PasskeyAccount(payable(alice)).execute(address(counter), 0, data, r, s);
        vm.expectRevert(PasskeyAccount.BadSignature.selector);
        PasskeyAccount(payable(alice)).execute(address(counter), 0, data, r, s);
        assertEq(counter.count(), 1);
    }

    function test_SequentialNonces() public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        for (uint256 i; i < 3; i++) {
            (bytes32 r, bytes32 s) = _sign(passkey, alice, address(counter), 0, data, i);
            PasskeyAccount(payable(alice)).execute(address(counter), 0, data, r, s);
        }
        assertEq(counter.count(), 3);
    }

    function test_WrongPasskeyFails() public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        (bytes32 r, bytes32 s) = _sign(0xBAD, alice, address(counter), 0, data, 0);
        vm.expectRevert(PasskeyAccount.BadSignature.selector);
        PasskeyAccount(payable(alice)).execute(address(counter), 0, data, r, s);
    }

    function test_TamperedCallFails() public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        (bytes32 r, bytes32 s) = _sign(passkey, alice, address(counter), 0, data, 0);
        vm.expectRevert(PasskeyAccount.BadSignature.selector);
        PasskeyAccount(payable(alice)).execute(address(counter), 1 ether, data, r, s); // value changed
    }

    function test_HighSRejected() public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        (bytes32 r, bytes32 s) = _sign(passkey, alice, address(counter), 0, data, 0);
        bytes32 highS = bytes32(N - uint256(s)); // also a valid P-256 sig, the malleable twin
        vm.expectRevert(PasskeyAccount.BadSignature.selector);
        PasskeyAccount(payable(alice)).execute(address(counter), 0, data, r, highS);
    }

    function test_CrossAccountReplayFails() public {
        // bob delegates to the same impl and registers the SAME passkey
        uint256 bobPk = 0xB0B;
        address bob = vm.addr(bobPk);
        vm.signAndAttachDelegation(address(impl), bobPk);
        vm.prank(bob);
        PasskeyAccount(payable(bob)).initialize(qx, qy);

        bytes memory data = abi.encodeCall(Counter.bump, ());
        (bytes32 r, bytes32 s) = _sign(passkey, alice, address(counter), 0, data, 0);
        vm.expectRevert(PasskeyAccount.BadSignature.selector);
        PasskeyAccount(payable(bob)).execute(address(counter), 0, data, r, s);
    }

    function test_InitializeOnlySelf() public {
        uint256 carolPk = 0xCA401;
        address carol = vm.addr(carolPk);
        vm.signAndAttachDelegation(address(impl), carolPk);
        vm.prank(relayer); // attacker tries to plant their key
        vm.expectRevert(PasskeyAccount.OnlySelf.selector);
        PasskeyAccount(payable(carol)).initialize(1, 2);
    }

    function test_CannotReinitialize() public {
        vm.prank(alice);
        vm.expectRevert(PasskeyAccount.AlreadyInitialized.selector);
        PasskeyAccount(payable(alice)).initialize(1, 2);
    }

    function testFuzz_RandomSigFails(bytes32 r, bytes32 s) public {
        bytes memory data = abi.encodeCall(Counter.bump, ());
        vm.expectRevert(PasskeyAccount.BadSignature.selector);
        PasskeyAccount(payable(alice)).execute(address(counter), 0, data, r, s);
    }
}
