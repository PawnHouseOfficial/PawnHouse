pragma solidity ^0.5.16;

/**
 * @title Elliptic curve signature operations
 * @dev Based on https://gist.github.com/axic/5b33912c6f61ae6fd96d6c4a47afde6d
 * TODO Remove this library once solidity supports passing a signature to ecrecover.
 * See https://github.com/ethereum/solidity/issues/864
 */

library ECDSA {
    /**
     * @dev Recover signer address from a message by using their signature
     * @param hash bytes32 message, the hash is the signed message. What is recovered is the signer address.
     * @param signature bytes signature, the signature is generated using web3.eth.sign()
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        if (signature.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            return ecrecover(hash, v, r, s);
        }
    }

    /**
     * toEthSignedMessageHash
     * @dev prefix a bytes32 value with "\x19Ethereum Signed Message:"
     * and hash the result
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}


// @title  Helper contract for PH. This contract manages verifying signatures
//         from off-chain PH orders.
// @author smartcontractdev.eth, creator of wrappedkitties.eth, cwhelper.eth,
//         and kittybounties.eth
// @notice Cite: I found the following article very insightful while creating
//         this contract:
//         https://dzone.com/articles/signing-and-verifying-ethereum-signatures
// @notice Cite: I also relied on this article somewhat:
//         https://forum.openzeppelin.com/t/sign-it-like-you-mean-it-creating-and-verifying-ethereum-signatures/697
contract PHSigningUtils {

    /* *********** */
    /* CONSTRUCTOR */
    /* *********** */

    constructor() internal {}

    /* ********* */
    /* FUNCTIONS */
    /* ********* */

    // @notice OpenZeppelin's ECDSA library is used to call all ECDSA functions
    //         directly on the bytes32 variables themselves.
    using ECDSA for bytes32;

    // @notice This function gets the current chain ID.
    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    // @notice This function is called in PH.beginLoan() to validate the
    //         borrower's signature that the borrower provided off-chain to
    //         verify that they did indeed want to use this NFT for this loan.
    // @param  _nftCollateralId - The ID within the NFTCollateralContract for
    //         the NFT being used as collateral for this loan. The NFT is
    //         stored within this contract during the duration of the loan.
    // @param  _borrowerNonce - The nonce referred to here
    //         is not the same as an Ethereum account's nonce. We are referring
    //         instead to nonces that are used by both the lender and the
    //         borrower when they are first signing off-chain PH orders.
    //         These nonces can be any uint256 value that the user has not
    //         previously used to sign an off-chain order. Each nonce can be
    //         used at most once per user within PH, regardless of whether
    //         they are the lender or the borrower in that situation. This
    //         serves two purposes. First, it prevents replay attacks where an
    //         attacker would submit a user's off-chain order more than once.
    //         Second, it allows a user to cancel an off-chain order by calling
    //         PH.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    // @param  _nftCollateralContract - The ERC721 contract of the NFT
    //         collateral
    // @param  _borrower - The address of the borrower.
    // @param  _borrowerSignature - The ECDSA signature of the borrower,
    //         obtained off-chain ahead of time, signing the following
    //         combination of parameters: _nftCollateralId, _borrowerNonce,
    //         _nftCollateralContract, _borrower.
    // @return A bool representing whether verification succeeded, showing that
    //         this signature matched this address and parameters.
    function isValidLenderSignature(
        uint256 _nftCollateralId,
        uint256 _lenderNonce,
        address _nftCollateralContract,
        address _lender,
        bytes memory _lenderSignature
    ) public view returns(bool) {
        if(_lender == address(0)){
            return false;
        } else {
            uint256 chainId;
            chainId = getChainID();
            bytes32 message = keccak256(abi.encodePacked(
                _nftCollateralId,
                _lenderNonce,
                _nftCollateralContract,
                _lender,
                chainId
            ));

            bytes32 messageWithEthSignPrefix = message.toEthSignedMessageHash();
            
            return (messageWithEthSignPrefix.recover(_lenderSignature) == _lender);
        }
    }

    // @notice This function is called in PH.beginLoan() to validate the
    //         lender's signature that the lender provided off-chain to
    //         verify that they did indeed want to agree to this loan according
    //         to these terms.
    // @param  _loanPrincipalAmount - The original sum of money transferred
    //         from lender to borrower at the beginning of the loan, measured
    //         in loanERC20Denomination's smallest units.
    // @param  _maximumRepaymentAmount - The maximum amount of money that the
    //         borrower would be required to retrieve their collateral. If
    //         interestIsProRated is set to false, then the borrower will
    //         always have to pay this amount to retrieve their collateral.
    // @param  _nftCollateralId - The ID within the NFTCollateralContract for
    //         the NFT being used as collateral for this loan. The NFT is
    //         stored within this contract during the duration of the loan.
    // @param  _loanDuration - The amount of time (measured in seconds) that can
    //         elapse before the lender can liquidate the loan and seize the
    //         underlying collateral NFT.
    // @param  _loanInterestRateForDurationInBasisPoints - The interest rate
    //         (measured in basis points, e.g. hundreths of a percent) for the
    //         loan, that must be repaid pro-rata by the borrower at the
    //         conclusion of the loan or risk seizure of their nft collateral.
    // @param  _adminFeeInBasisPoints - The percent (measured in basis
    //         points) of the interest earned that will be taken as a fee by
    //         the contract admins when the loan is repaid. The fee is stored
    //         in the loan struct to prevent an attack where the contract
    //         admins could adjust the fee right before a loan is repaid, and
    //         take all of the interest earned.
    // @param  _lenderNonce - The nonce referred to here
    //         is not the same as an Ethereum account's nonce. We are referring
    //         instead to nonces that are used by both the lender and the
    //         borrower when they are first signing off-chain PH orders.
    //         These nonces can be any uint256 value that the user has not
    //         previously used to sign an off-chain order. Each nonce can be
    //         used at most once per user within PH, regardless of whether
    //         they are the lender or the borrower in that situation. This
    //         serves two purposes. First, it prevents replay attacks where an
    //         attacker would submit a user's off-chain order more than once.
    //         Second, it allows a user to cancel an off-chain order by calling
    //         PH.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    // @param  _nftCollateralContract - The ERC721 contract of the NFT
    //         collateral
    // @param  _loanERC20Denomination - The ERC20 contract of the currency being
    //         used as principal/interest for this loan.
    // @param  _lender - The address of the lender. The lender can change their
    //         address by transferring the PH ERC721 token that they
    //         received when the loan began.
    // @param  _interestIsProRated - A boolean value determining whether the
    //         interest will be pro-rated if the loan is repaid early, or
    //         whether the borrower will simply pay maximumRepaymentAmount.
    // @param  _lenderSignature - The ECDSA signature of the lender,
    //         obtained off-chain ahead of time, signing the following
    //         combination of parameters: _loanPrincipalAmount,
    //         _maximumRepaymentAmount _nftCollateralId, _loanDuration,
    //         _loanInterestRateForDurationInBasisPoints, _lenderNonce,
    //         _nftCollateralContract, _loanERC20Denomination, _lender,
    //         _interestIsProRated.
    // @return A bool representing whether verification succeeded, showing that
    //         this signature matched this address and parameters.
    function isValidBorrowSignature(
        uint256 _loanPrincipalAmount,
        uint256 _maximumRepaymentAmount,
        uint256 _nftCollateralId,
        uint256 _loanDuration,
        uint256 _loanInterestRateForDurationInBasisPoints,
        uint256 _adminFeeInBasisPoints,
        uint256 _borrowerNonce,
        address _nftCollateralContract,
        address _loanERC20Denomination,
        address _borrower,
        bool _interestIsProRated,
        bytes memory _lenderSignature
    ) public view returns(bool) {
        if(_borrower == address(0)){
            return false;
        } else {
            uint256 chainId;
            chainId = getChainID();
            bytes32 message = keccak256(abi.encodePacked(
                _loanPrincipalAmount,
                _maximumRepaymentAmount,
                _nftCollateralId,
                _loanDuration,
                _loanInterestRateForDurationInBasisPoints,
                _adminFeeInBasisPoints,
                _borrowerNonce,
                _nftCollateralContract,
                _loanERC20Denomination,
                _borrower,
                _interestIsProRated,
                chainId
            ));

            bytes32 messageWithEthSignPrefix = message.toEthSignedMessageHash();

            return (messageWithEthSignPrefix.recover(_lenderSignature) == _borrower);
        }
    }
}