// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title PasskeyAccount
/// @notice Delegation target for an EIP-7702 EOA. The EOA's own storage holds a
///         P-256 (secp256r1) public key; anyone can relay a call as long as it
///         carries a valid P-256 signature over (chainid, account, nonce, call).
/// @dev    Demo only. Verifies a RAW P-256 signature over a digest. A real
///         passkey (WebAuthn) signs sha256(authenticatorData || sha256(clientDataJSON)),
///         which you'd have to rebuild on-chain before calling the precompile.
contract PasskeyAccount {
    /// EIP-7951 P256VERIFY precompile.
    address internal constant P256VERIFY = address(0x100);
    /// secp256r1 group order n, and n/2 for the low-s check.
    uint256 internal constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant HALF_N = N / 2;

    // NOTE: 7702 accounts share storage with whatever was delegated before.
    // Production code should use a namespaced slot (ERC-7201). Kept simple here.
    uint256 public qx;
    uint256 public qy;
    uint256 public nonce;

    error AlreadyInitialized();
    error OnlySelf();
    error BadSignature();
    error CallFailed(bytes ret);

    event PasskeySet(uint256 qx, uint256 qy);
    event Executed(uint256 indexed nonce, address target, uint256 value);

    /// Must be called by the EOA itself (msg.sender == address(this)),
    /// so nobody can front-run and plant their own key.
    function initialize(uint256 _qx, uint256 _qy) external {
        if (msg.sender != address(this)) revert OnlySelf();
        if (qx != 0 || qy != 0) revert AlreadyInitialized();
        qx = _qx;
        qy = _qy;
        emit PasskeySet(_qx, _qy);
    }

    function digest(address target, uint256 value, bytes calldata data, uint256 _nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), _nonce, target, value, keccak256(data)));
    }

    function execute(address target, uint256 value, bytes calldata data, bytes32 r, bytes32 s)
        external
        returns (bytes memory)
    {
        uint256 n = nonce;
        bytes32 h = digest(target, value, data, n);
        if (!_verify(h, r, s)) revert BadSignature();
        nonce = n + 1; // bump before the external call
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        emit Executed(n, target, value);
        return ret;
    }

    function _verify(bytes32 h, bytes32 r, bytes32 s) internal view returns (bool) {
        // P-256 sigs are malleable (EIP-7951 says so); reject the high-s twin.
        if (uint256(s) > HALF_N) return false;
        if (qx == 0 && qy == 0) return false;
        (bool ok, bytes memory out) = P256VERIFY.staticcall(abi.encode(h, r, s, qx, qy));
        // Success = 32 bytes of 1. Failure = empty return data (never reverts).
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    receive() external payable {}
}
