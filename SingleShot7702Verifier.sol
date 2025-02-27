// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// By Alex Watts (@ThogardPvP) and based off of the Biconomy PREP design (https://blog.biconomy.io/prep-deep-dive/)
// Per EIP-7702 (https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7702.md).
// Rather than using provable randomness, this design uses a complete lack of randomness to allow verification
// of 7702-ness
// This is a sketched concept - it will not work in prod until updated so that the payload is packed properly.

// The purpose is to verify that a 7702-activated address does not have a knowable private key and is therefore
// immutable. The deployer of the 7702-activated address must know this factory address prior to deployment.
contract SingleShot7702Verifier {
    error UnableToGenerateSignature(uint256 maxAttempts);

    // 7702's magic salt
    uint8 public constant MAGIC = 0x05;

    // 7702's salt for authority's codehash
    bytes3 public constant EIP_7702_CODE_HASH_SALT = bytes3(0xef0100);

    // The address of the smart contract with the bytecode delegated to by the 7702-activated account
    address public immutable DELEGATION;

    constructor(address delegationDesignation) {
        DELEGATION = delegationDesignation;
    }

    // This assumes a signature for an EOA was generated without a private key. This process would be in line with
    // Nick's method (https://medium.com/patronum-labs/nicks-method-ethereum-keyless-execution-168a6659479c).
    // By seeding the signature with known addresses, we can verify deterministically that a 7702-enabled EOA
    // was generated without knowledge of the private key, making it cryptographically 'very very difficult'
    // for anyone to increment the nonce thereby invalidating the private key.

    // This function allows anyone with knowledge of 'seedAddress' to verify that 'target' is a 7702 single shot account
    // that cannot have its nonce incremented.
    // NOTE: The seedAddress could be either an initial "owner" or a registry contract that points to the owner.
    function validate(address target, address seedAddress, uint256 maxAttempts) external view returns (bool valid) {
        require(maxAttempts < type(uint24).max, "Too Many Attempts");

        // Make sure that the target is already deployed (IE we weren't looking at a reorg and now the target doesnt yet
        // exist)
        // Per EIP-7702: "EXTCODEHASH would return keccak256(0xef0100 || address)".
        // TODO: Pack properly
        if (target.codehash != keccak256(abi.encodePacked(EIP_7702_CODE_HASH_SALT, target))) return false;

        // Generate the hash of the payload that's signed with the single-shot signature
        bytes32 payloadHash = getPayloadHash();

        // Define variables
        uint8 v = 28;
        bytes32 r;
        uint256 s;

        address factory = address(this);
        address delegation = DELEGATION;
        uint256 retryToFindAValidAddressAttempts = 0;

        /*
        Initialize the fixed variables:

        r = ||                  factory  = 20 bytes                     |    first part of seed = 12 bytes        || 
        s = |00| second part of seed = 8 bytes |           implementation = 20 bytes              | retry* =3bytes||
        v = |28|

        */
        assembly {
            r := or(shl(96, factory), shr(64, seedAddress))
            s := or(shl(184, seedAddress), shl(24, delegation))
        }

        // NOTE: The chance of deriving a valid address from a random signature is approximately 50%
        for (; retryToFindAValidAddressAttempts < maxAttempts; retryToFindAValidAddressAttempts++) {
            if (target == ecrecover(payloadHash, v, r, bytes32(s))) {
                return true;
            }
            unchecked {
                ++s;
            } // what a throwback
        }
        return false;
    }

    // A helper function to help with single-shot signature creation
    function generateSignature(
        address seedAddress,
        uint256 maxAttempts
    )
        external
        view
        returns (address target, uint8 v, bytes32 r, bytes32 s)
    {
        // Generate the hash of the payload that's signed with the single-shot signature
        bytes32 payloadHash = getPayloadHash();

        // Define variables
        uint8 _v = 28;
        uint256 _r; // a uint implementation of r for readability
        uint256 _s; // a uint implementation of s for readability

        address factory = address(this);
        address delegation = DELEGATION;
        uint256 retryToFindAValidAddressAttempts = 0;

        /*
        Initialize the fixed variables:

        r = ||                  factory  = 20 bytes                     |    first part of seed = 12 bytes        || 
        s = |00| second part of seed = 8 bytes |           implementation = 20 bytes              | retry* =3bytes||
        v = |28|

        */
        assembly {
            _r := or(shl(96, factory), shr(64, seedAddress))
            _s := or(shl(184, seedAddress), shl(24, delegation))
        }

        // NOTE: The chance of deriving a valid address from a random signature is approximately 50%
        for (; retryToFindAValidAddressAttempts < maxAttempts; retryToFindAValidAddressAttempts++) {
            target = ecrecover(payloadHash, _v, bytes32(_r), bytes32(_s));
            if (target != address(0)) {
                return (target, _v, bytes32(_r), bytes32(_s));
            }
            unchecked {
                ++_s;
            } // what a throwback
        }
        // Revert if we cannot generate the signature within the alloted max attempts
        revert UnableToGenerateSignature(maxAttempts);
    }

    // Returns the EIP-7702 Payload
    function getPayload() public view returns (bytes memory payload) {
        // Payload components
        uint256 chainId = 0; // 0 to work on all chains.
        uint256 nonce = 0; // Nonce must be zero or the single-shot tx cannot execute.

        // Generate the payload
        // TODO: Pack correctly
        payload = abi.encodePacked(
            MAGIC,
            abi.encode(
                chainId,
                DELEGATION,
                nonce // <- TODO: This is RLP encoded
            )
        );
    }

    // Returns the hash of the EIP-7702 Payload
    function getPayloadHash() public view returns (bytes32 payloadHash) {
        payloadHash = keccak256(getPayload());
    }
}
