pragma solidity ^0.5.16;

import './PHAdmin.sol';
import './ERC721.sol';
import './PHSigningUtils.sol';

/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);

    function approve(address spender, uint256 value) external returns (bool);

    function transferFrom(address from, address to, uint256 value) external returns (bool);

    function totalSupply() external view returns (uint256);

    function balanceOf(address who) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}


pragma solidity ^0.5.16;






// @title  Main contract for PH. This contract manages the ability to create
//         NFT-backed peer-to-peer loans.
// @author smartcontractdev.eth, creator of wrappedkitties.eth, cwhelper.eth, and
//         kittybounties.eth
// @notice There are five steps needed to commence an NFT-backed loan. First,
//         the borrower calls nftContract.approveAll(PH), approving the PH
//         contract to move their NFT's on their behalf. Second, the borrower
//         signs an off-chain message for each NFT that they would like to
//         put up for collateral. This prevents borrowers from accidentally
//         lending an NFT that they didn't mean to lend, due to approveAll()
//         approving their entire collection. Third, the lender calls
//         erc20Contract.approve(PH), allowing PH to move the lender's
//         ERC20 tokens on their behalf. Fourth, the lender signs an off-chain
//         message, proposing the amount, rate, and duration of a loan for a
//         particular NFT. Fifth, the borrower calls PH.beginLoan() to
//         accept these terms and enter into the loan. The NFT is stored in the
//         contract, the borrower receives the loan principal in the specified
//         ERC20 currency, and the lender receives an PH promissory note (in
//         ERC721 form) that represents the rights to either the
//         principal-plus-interest, or the underlying NFT collateral if the
//         borrower does not pay back in time. The lender can freely transfer
//         and trade this ERC721 promissory note as they wish, with theq
//         knowledge that transferring the ERC721 promissory note tranfsers the
//         rights to principal-plus-interest and/or collateral, and that they
//         will no longer have a claim on the loan. The ERC721 promissory note
//         itself represents that claim.
// @notice A loan may end in one of two ways. First, a borrower may call
//         PH.payBackLoan() and pay back the loan plus interest at any time,
//         in which case they receive their NFT back in the same transaction.
//         Second, if the loan's duration has passed and the loan has not been
//         paid back yet, a lender can call PH.liquidateOverdueLoan(), in
//         which case they receive the underlying NFT collateral and forfeit
//         the rights to the principal-plus-interest, which the borrower now
//         keeps.
// @notice If the loan was agreed to be a pro-rata interest loan, then the user
//         only pays the principal plus pro-rata interest if repaid early.
//         However, if the loan was agreed to be a fixed-repayment loan (by
//         specifying UINT32_MAX as the value for
//         loanInterestRateForDurationInBasisPoints), then the borrower pays
//         the maximumRepaymentAmount regardless of whether they repay early
//         or not.
contract PawnHouseLoan is PHAdmin, PHSigningUtils, ERC721 {

    // @notice OpenZeppelin's SafeMath library is used for all arithmetic
    //         operations to avoid overflows/underflows.
    using SafeMath for uint256;

    /* ********** */
    /* DATA TYPES */
    /* ********** */

    // @notice The main Loan struct. The struct fits in six 256-bits words due
    //         to Solidity's rules for struct packing.
    struct Loan {
        // A unique identifier for this particular loan, sourced from the
        // continuously increasing parameter totalNumLoans.
        uint256 loanId;
        // The original sum of money transferred from lender to borrower at the
        // beginning of the loan, measured in loanERC20Denomination's smallest
        // units.
        uint256 loanPrincipalAmount;
        // The maximum amount of money that the borrower would be required to
        // repay retrieve their collateral, measured in loanERC20Denomination's
        // smallest units. If interestIsProRated is set to false, then the
        // borrower will always have to pay this amount to retrieve their
        // collateral, regardless of whether they repay early.
        uint256 maximumRepaymentAmount;
        // The ID within the NFTCollateralContract for the NFT being used as
        // collateral for this loan. The NFT is stored within this contract
        // during the duration of the loan.
        uint256 nftCollateralId;
        // The block.timestamp when the loan first began (measured in seconds).
        uint64 loanStartTime;
        // The amount of time (measured in seconds) that can elapse before the
        // lender can liquidate the loan and seize the underlying collateral.
        uint32 loanDuration;
        // If interestIsProRated is set to true, then this is the interest rate
        // (measured in basis points, e.g. hundreths of a percent) for the loan,
        // that must be repaid pro-rata by the borrower at the conclusion of
        // the loan or risk seizure of their nft collateral. Note that if
        // interestIsProRated is set to false, then this value is not used and
        // is irrelevant.
        uint32 loanInterestRateForDurationInBasisPoints;
        // The percent (measured in basis points) of the interest earned that
        // will be taken as a fee by the contract admins when the loan is
        // repaid. The fee is stored here to prevent an attack where the
        // contract admins could adjust the fee right before a loan is repaid,
        // and take all of the interest earned.
        uint32 loanAdminFeeInBasisPoints;
        // The ERC721 contract of the NFT collateral
        address nftCollateralContract;
        // The ERC20 contract of the currency being used as principal/interest
        // for this loan.
        address loanERC20Denomination;
        // The address of the borrower.
        address borrower;
        // A boolean value determining whether the interest will be pro-rated
        // if the loan is repaid early, or whether the borrower will simply
        // pay maximumRepaymentAmount.
        bool interestIsProRated;
    }

    /* ****** */
    /* EVENTS */
    /* ****** */

    // @notice This event is fired whenever a borrower begins a loan by calling
    //         PH.beginLoan(), which can only occur after both the lender
    //         and borrower have approved their ERC721 and ERC20 contracts to
    //         use PH, and when they both have signed off-chain messages that
    //         agree on the terms of the loan.
    // @param  loanId - A unique identifier for this particular loan, sourced
    //         from the continuously increasing parameter totalNumLoans.
    // @param  borrower - The address of the borrower.
    // @param  lender - The address of the lender. The lender can change their
    //         address by transferring the PH ERC721 token that they
    //         received when the loan began.
    // @param  loanPrincipalAmount - The original sum of money transferred from
    //         lender to borrower at the beginning of the loan, measured in
    //         loanERC20Denomination's smallest units.
    // @param  maximumRepaymentAmount - The maximum amount of money that the
    //         borrower would be required to retrieve their collateral. If
    //         interestIsProRated is set to false, then the borrower will
    //         always have to pay this amount to retrieve their collateral.
    // @param  nftCollateralId - The ID within the NFTCollateralContract for the
    //         NFT being used as collateral for this loan. The NFT is stored
    //         within this contract during the duration of the loan.
    // @param  loanStartTime - The block.timestamp when the loan first began
    //         (measured in seconds).
    // @param  loanDuration - The amount of time (measured in seconds) that can
    //         elapse before the lender can liquidate the loan and seize the
    //         underlying collateral NFT.
    // @param  loanInterestRateForDurationInBasisPoints - If interestIsProRated
    //         is set to true, then this is the interest rate (measured in
    //         basis points, e.g. hundreths of a percent) for the loan, that
    //         must be repaid pro-rata by the borrower at the conclusion of the
    //         loan or risk seizure of their nft collateral. Note that if
    //         interestIsProRated is set to false, then this value is not used
    //         and is irrelevant.
    // @param  nftCollateralContract - The ERC721 contract of the NFT collateral
    // @param  loanERC20Denomination - The ERC20 contract of the currency being
    //         used as principal/interest for this loan.
    // @param  interestIsProRated - A boolean value determining whether the
    //         interest will be pro-rated if the loan is repaid early, or
    //         whether the borrower will simply pay maximumRepaymentAmount.
    event LoanStarted(
        uint256 loanId,
        address borrower,
        address lender,
        uint256 loanPrincipalAmount,
        uint256 maximumRepaymentAmount,
        uint256 nftCollateralId,
        uint256 loanStartTime,
        uint256 loanDuration,
        uint256 loanInterestRateForDurationInBasisPoints,
        address nftCollateralContract,
        uint256 borrower_nonce,  
        uint256 lender_nonce    
    );
    
    event LoanFee(
        uint256 loanId,
        address borrower,
        address lender,
        uint256 fee,
        uint256 reward,
        address loanERC20Denomination,
        bool interestIsProRated
    );

    // @notice This event is fired whenever a borrower successfully repays
    //         their loan, paying principal-plus-interest-minus-fee to the
    //         lender in loanERC20Denomination, paying fee to owner in
    //         loanERC20Denomination, and receiving their NFT collateral back.
    // @param  loanId - A unique identifier for this particular loan, sourced
    //         from the continuously increasing parameter totalNumLoans.
    // @param  borrower - The address of the borrower.
    // @param  lender - The address of the lender. The lender can change their
    //         address by transferring the PH ERC721 token that they
    //         received when the loan began.
    // @param  loanPrincipalAmount - The original sum of money transferred from
    //         lender to borrower at the beginning of the loan, measured in
    //         loanERC20Denomination's smallest units.
    // @param  nftCollateralId - The ID within the NFTCollateralContract for the
    //         NFT being used as collateral for this loan. The NFT is stored
    //         within this contract during the duration of the loan.
    // @param  amountPaidToLender The amount of ERC20 that the borrower paid to
    //         the lender, measured in the smalled units of
    //         loanERC20Denomination.
    // @param  adminFee The amount of interest paid to the contract admins,
    //         measured in the smalled units of loanERC20Denomination and
    //         determined by adminFeeInBasisPoints. This amount never exceeds
    //         the amount of interest earned.
    // @param  nftCollateralContract - The ERC721 contract of the NFT collateral
    // @param  loanERC20Denomination - The ERC20 contract of the currency being
    //         used as principal/interest for this loan.
    event LoanRepaid(
        uint256 loanId,
        address borrower,
        address lender,
        uint256 loanPrincipalAmount,
        uint256 nftCollateralId,
        uint256 amountPaidToLender,
        address nftCollateralContract,
        address loanERC20Denomination
    );

    // @notice This event is fired whenever a lender liquidates an outstanding
    //         loan that is owned to them that has exceeded its duration. The
    //         lender receives the underlying NFT collateral, and the borrower
    //         no longer needs to repay the loan principal-plus-interest.
    // @param  loanId - A unique identifier for this particular loan, sourced
    //         from the continuously increasing parameter totalNumLoans.
    // @param  borrower - The address of the borrower.
    // @param  lender - The address of the lender. The lender can change their
    //         address by transferring the PH ERC721 token that they
    //         received when the loan began.
    // @param  loanPrincipalAmount - The original sum of money transferred from
    //         lender to borrower at the beginning of the loan, measured in
    //         loanERC20Denomination's smallest units.
    // @param  nftCollateralId - The ID within the NFTCollateralContract for the
    //         NFT being used as collateral for this loan. The NFT is stored
    //         within this contract during the duration of the loan.
    // @param  loanMaturityDate - The unix time (measured in seconds) that the
    //         loan became due and was eligible for liquidation.
    // @param  loanLiquidationDate - The unix time (measured in seconds) that
    //         liquidation occurred.
    // @param  nftCollateralContract - The ERC721 contract of the NFT collateral
    event LoanLiquidated(
        uint256 loanId,
        address borrower,
        address lender,
        uint256 loanPrincipalAmount,
        uint256 nftCollateralId,
        uint256 loanMaturityDate,
        uint256 loanLiquidationDate,
        address nftCollateralContract
    );


    /* ******* */
    /* STORAGE */
    /* ******* */

    // @notice A continuously increasing counter that simultaneously allows
    //         every loan to have a unique ID and provides a running count of
    //         how many loans have been started by this contract.
    uint256 public totalNumLoans = 0;

    // @notice A counter of the number of currently outstanding loans.
    uint256 public totalActiveLoans = 0;
    
    
    uint256 public totalDayReward = 657534000000000000000000;


    uint256 public leftReward = 657534000000000000000000;


    uint256 public totalDayRewardPreUp = 1;
    uint256 public totalDayRewardPreDown = 1;
    
    uint256 public startime = 1625418000;

    uint256 public constant DURATION = 1 days;


    address public  rewardToken;
    
    address public  funder;
    
    PriceQuery priceQ;


    // @notice A mapping from a loan's identifier to the loan's details,
    //         represted by the loan struct. To fetch the lender, call
    //         PH.ownerOf(loanId).
    mapping (uint256 => Loan) public loanIdToLoan;

    // @notice A mapping tracking whether a loan has either been repaid or
    //         liquidated. This prevents an attacker trying to repay or
    //         liquidate the same loan twice.
    mapping (uint256 => bool) public loanRepaidOrLiquidated;

    // @notice A mapping that takes both a user's address and a loan nonce
    //         that was first used when signing an off-chain order and checks
    //         whether that nonce has previously either been used for a loan,
    //         or has been pre-emptively cancelled. The nonce referred to here
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
    mapping (address => mapping (uint256 => bool)) private _nonceHasBeenUsedForUser;

    /* *********** */
    /* CONSTRUCTOR */
    /* *********** */

    constructor(address rewardToken_,address funder_,address priceAddress_) public {
        rewardToken=rewardToken_;
        funder=funder_;
        priceQ=PriceQuery(priceAddress_);
    }

    /* ********* */
    /* FUNCTIONS */
    /* ********* */

    // @notice This function is called by a borrower when they want to commence
    //         a loan, but can only be called after first: (1) the borrower has
    //         called approve() or approveAll() on the NFT contract for the NFT
    //         that will be used as collateral, (2) the borrower has signed an
    //         off-chain message indicating that they are willing to use this
    //         NFT as collateral, (3) the lender has called approve() on the
    //         ERC20 contract of the principal, and (4) the lender has signed
    //         an off-chain message agreeing to the terms of this loan supplied
    //         in this transaction.
    // @notice Note that a user may submit UINT32_MAX as the value for
    //         _loanInterestRateForDurationInBasisPoints to indicate that they
    //         wish to take out a fixed-repayment loan, where the interest is
    //         not pro-rated if repaid early.
    // @param  _loanPrincipalAmount - The original sum of money transferred
    //         from lender to borrower at the beginning of the loan, measured
    //         in loanERC20Denomination's smallest units.
    // @param  _maximumRepaymentAmount - The maximum amount of money that the
    //         borrower would be required to retrieve their collateral,
    //         measured in the smallest units of the ERC20 currency used for
    //         the loan. If interestIsProRated is set to false (by submitting
    //         a value of UINT32_MAX for
    //         _loanInterestRateForDurationInBasisPoints), then the borrower
    //         will always have to pay this amount to retrieve their
    //         collateral, regardless of whether they repay early.
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
    //         However, a user may submit UINT32_MAX as the value for
    //         _loanInterestRateForDurationInBasisPoints to indicate that they
    //         wish to take out a fixed-repayment loan, where the interest is
    //         not pro-rated if repaid early. Instead, maximumRepaymentAmount
    //         will always be the amount to be repaid.
    // @param  _adminFeeInBasisPoints - The percent (measured in basis
    //         points) of the interest earned that will be taken as a fee by
    //         the contract admins when the loan is repaid. The fee is stored
    //         in the loan struct to prevent an attack where the contract
    //         admins could adjust the fee right before a loan is repaid, and
    //         take all of the interest earned.
    // @param  _borrowerAndLenderNonces - An array of two UINT256 values, the
    //         first of which is the _borrowerNonce and the second of which is
    //         the _lenderNonce. The nonces referred to here are not the same
    //         as an Ethereum account's nonce. We are referring instead to
    //         nonces that are used by both the lender and the borrower when
    //         they are first signing off-chain PH orders. These nonces can
    //         be any uint256 value that the user has not previously used to
    //         sign an off-chain order. Each nonce can be used at most once per
    //         user within PH, regardless of whether they are the lender or
    //         the borrower in that situation. This serves two purposes. First,
    //         it prevents replay attacks where an attacker would submit a
    //         user's off-chain order more than once. Second, it allows a user
    //         to cancel an off-chain order by calling
    //         PH.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    // @param  _nftCollateralContract - The address of the ERC721 contract of
    //         the NFT collateral.
    // @param  _loanERC20Denomination - The address of the ERC20 contract of
    //         the currency being used as principal/interest for this loan.
    // @param  _lender - The address of the lender. The lender can change their
    //         address by transferring the PH ERC721 token that they
    //         received when the loan began.
    // @param  _borrowerSignature - The ECDSA signature of the borrower,
    //         obtained off-chain ahead of time, signing the following
    //         combination of parameters: _nftCollateralId, _borrowerNonce,
    //         _nftCollateralContract, _borrower.
    // @param  _lenderSignature - The ECDSA signature of the lender,
    //         obtained off-chain ahead of time, signing the following
    //         combination of parameters: _loanPrincipalAmount,
    //         _maximumRepaymentAmount _nftCollateralId, _loanDuration,
    //         _loanInterestRateForDurationInBasisPoints, _lenderNonce,
    //         _nftCollateralContract, _loanERC20Denomination, _lender,
    //         _interestIsProRated.
    function beginLoan(
        uint256 _loanPrincipalAmount,
        uint256 _maximumRepaymentAmount,
        uint256 _nftCollateralId,
        uint256 _loanDuration,
        uint256 _loanInterestRateForDurationInBasisPoints,
        uint256 _adminFeeInBasisPoints,
        uint256[2] memory _borrowerAndLenderNonces,
        address _nftCollateralContract,
        address _loanERC20Denomination,
        address _borrower,
        bytes memory _borrowerSignature,
        bytes memory _lenderSignature
    ) public whenNotPaused nonReentrant checkhalve {

        // Save loan details to a struct in memory first, to save on gas if any
        // of the below checks fail, and to avoid the "Stack Too Deep" error by
        // clumping the parameters together into one struct held in memory.
        Loan memory loan = Loan({
            loanId: totalNumLoans, //currentLoanId,
            loanPrincipalAmount: _loanPrincipalAmount,
            maximumRepaymentAmount: _maximumRepaymentAmount,
            nftCollateralId: _nftCollateralId,
            loanStartTime: uint64(now), //_loanStartTime
            loanDuration: uint32(_loanDuration),
            loanInterestRateForDurationInBasisPoints: uint32(_loanInterestRateForDurationInBasisPoints),
            loanAdminFeeInBasisPoints: uint32(_adminFeeInBasisPoints),
            nftCollateralContract: _nftCollateralContract,
            loanERC20Denomination: _loanERC20Denomination,
            borrower: _borrower, //lender
            interestIsProRated: (_loanInterestRateForDurationInBasisPoints != ~(uint32(0)))
        });

        // Sanity check loan values.
        require(loan.maximumRepaymentAmount >= loan.loanPrincipalAmount, 'Negative interest rate loans are not allowed.');
        require(uint256(loan.loanDuration) <= maximumLoanDuration, 'Loan duration exceeds maximum loan duration');
        require(uint256(loan.loanDuration) != 0, 'Loan duration cannot be zero');
        require(uint256(loan.loanAdminFeeInBasisPoints) == adminFeeInBasisPoints, 'The admin fee has changed since this order was signed.');

        // Check that both the collateral and the principal come from supported
        // contracts.
        require(erc20CurrencyIsWhitelisted[loan.loanERC20Denomination], 'Currency denomination is not whitelisted to be used by this contract');
        require(nftContractIsWhitelisted[loan.nftCollateralContract], 'NFT collateral contract is not whitelisted to be used by this contract');

        // Check loan nonces. These are different from Ethereum account nonces.
        // Here, these are uint256 numbers that should uniquely identify
        // each signature for each user (i.e. each user should only create one
        // off-chain signature for each nonce, with a nonce being any arbitrary
        // uint256 value that they have not used yet for an off-chain PH
        // signature).
        require(!_nonceHasBeenUsedForUser[_borrower][_borrowerAndLenderNonces[0]], 'Borrower nonce invalid, borrower has either cancelled/begun this loan, or reused this nonce when signing');
        _nonceHasBeenUsedForUser[_borrower][_borrowerAndLenderNonces[0]] = true;
        require(!_nonceHasBeenUsedForUser[msg.sender][_borrowerAndLenderNonces[1]], 'Lender nonce invalid, lender has either cancelled/begun this loan, or reused this nonce when signing');
        _nonceHasBeenUsedForUser[msg.sender][_borrowerAndLenderNonces[1]] = true;

        // Check that both signatures are valid.
        require(isValidLenderSignature(
            loan.nftCollateralId,
            _borrowerAndLenderNonces[1],//_lenderNonce,
            loan.nftCollateralContract,
            msg.sender,
            _lenderSignature
        ), 'Lender signature is invalid');
        require(isValidBorrowSignature(
            loan.loanPrincipalAmount,
            loan.maximumRepaymentAmount,
            loan.nftCollateralId,
            loan.loanDuration,
            loan.loanInterestRateForDurationInBasisPoints,
            loan.loanAdminFeeInBasisPoints,
            _borrowerAndLenderNonces[0],//_borrowerNonce,
            loan.nftCollateralContract,
            loan.loanERC20Denomination,
            _borrower,
            loan.interestIsProRated,
            _borrowerSignature
        ), 'borrower signature is invalid');

        // Add the loan to storage before moving collateral/principal to follow
        // the Checks-Effects-Interactions pattern.
        loanIdToLoan[totalNumLoans] = loan;
        totalNumLoans = totalNumLoans.add(1);

        // Update number of active loans.
        totalActiveLoans = totalActiveLoans.add(1);
        require(totalActiveLoans <= maximumNumberOfActiveLoans, 'Contract has reached the maximum number of active loans allowed by admins');

        // Transfer collateral from borrower to this contract to be held until
        // loan completion.
        IERC721(loan.nftCollateralContract).transferFrom(_borrower, address(this), loan.nftCollateralId);
         
        // Transfer principal from lender to borrower.
        uint256 adminFee = _computeAdminFee(loan.loanPrincipalAmount, uint256(loan.loanAdminFeeInBasisPoints));
        uint256 borrowAmount=loan.loanPrincipalAmount.sub(adminFee);
        IERC20(loan.loanERC20Denomination).transferFrom(msg.sender, funder, adminFee);

        IERC20(loan.loanERC20Denomination).transferFrom(msg.sender, _borrower, borrowAmount);
        uint256 reward=0;
        if(address(0x55d398326f99059fF775485246999027B3197955)==loan.loanERC20Denomination){
           reward=loan.loanPrincipalAmount.mul(totalDayRewardPreUp).div(totalDayRewardPreDown);
        }else if(address(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c)==loan.loanERC20Denomination){
            uint256 price=priceQ.getPrice(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x55d398326f99059fF775485246999027B3197955);
            reward=loan.loanPrincipalAmount.mul(totalDayRewardPreUp).mul(price).div(totalDayRewardPreDown).div(100000000);
        }
        if(reward>0){
            if(leftReward>0){
                if(reward<=leftReward){
                leftReward=leftReward.sub(reward);
                    IERC20(rewardToken).transfer(msg.sender, reward);
                }else{
                    reward=leftReward;
                    leftReward=0;
                    IERC20(rewardToken).transfer(msg.sender, reward);
                }
            }else{
               reward=leftReward; 
            }
        }
         emit LoanFee(
            loan.loanId,
            _borrower,
            msg.sender,
            adminFee,
            reward,
            loan.loanERC20Denomination,
            loan.interestIsProRated
        );

        // Issue an ERC721 promissory note to the lender that gives them the
        // right to either the principal-plus-interest or the collateral.
        _mint(msg.sender, loan.loanId);
        uint256 borrowerNonce=_borrowerAndLenderNonces[0];
        uint256 lenderNonce=_borrowerAndLenderNonces[1];

        // Emit an event with all relevant details from this transaction.
        emit LoanStarted(
            loan.loanId,
            _borrower,
            msg.sender,      //lender,
            loan.loanPrincipalAmount,
            loan.maximumRepaymentAmount,
            loan.nftCollateralId,
            now,             //_loanStartTime
            loan.loanDuration,
            loan.loanInterestRateForDurationInBasisPoints,
            loan.nftCollateralContract,
            borrowerNonce,
            lenderNonce
        );
    }

    // @notice This function is called by a borrower when they want to repay
    //         their loan. It can be called at any time after the loan has
    //         begun. The borrower will pay a pro-rata portion of their
    //         interest if the loan is paid off early. The interest will
    //         continue to accrue after the loan has expired. This function can
    //         continue to be called by the borrower even after the loan has
    //         expired to retrieve their NFT. Note that the lender can call
    //         PH.liquidateOverdueLoan() at any time after the loan has
    //         expired, so a borrower should avoid paying their loan after the
    //         due date, as they risk their collateral being seized. However,
    //         if a lender has called PH.liquidateOverdueLoan() before a
    //         borrower could call PH.payBackLoan(), the borrower will get
    //         to keep the principal-plus-interest.
    // @notice This function is purposefully not pausable in order to prevent
    //         an attack where the contract admin's pause the contract and hold
    //         hostage the NFT's that are still within it.
    // @param _loanId  A unique identifier for this particular loan, sourced
    //        from the continuously increasing parameter totalNumLoans.
    function payBackLoan(uint256 _loanId) external nonReentrant {
        // Sanity check that payBackLoan() and liquidateOverdueLoan() have
        // never been called on this loanId. Depending on how the rest of the
        // code turns out, this check may be unnecessary.
        require(!loanRepaidOrLiquidated[_loanId], 'Loan has already been repaid or liquidated');

        
        // Fetch loan details from storage, but store them in memory for the
        // sake of saving gas.
        Loan memory loan = loanIdToLoan[_loanId];


        uint256 loanMaturityDate = (uint256(loan.loanStartTime)).add(uint256(loan.loanDuration));
        require(now <=  loanMaturityDate, 'Loan is  overdue yet');
        // Check that the borrower is the caller, only the borrower is entitled
        // to the collateral.
        require(msg.sender == loan.borrower, 'Only the borrower can pay back a loan and reclaim the underlying NFT');

        // Fetch current owner of loan promissory note.
        address lender = ownerOf(_loanId);

        // Calculate amounts to send to lender and admins
        uint256 interestDue = (loan.maximumRepaymentAmount).sub(loan.loanPrincipalAmount);
        if(loan.interestIsProRated == true){
            interestDue = _computeInterestDue(
                loan.loanPrincipalAmount,
                loan.maximumRepaymentAmount,
                now.sub(uint256(loan.loanStartTime)),
                uint256(loan.loanDuration),
                uint256(loan.loanInterestRateForDurationInBasisPoints)
            );
        }
        uint256 payoffAmount = ((loan.loanPrincipalAmount).add(interestDue));

        // Mark loan as repaid before doing any external transfers to follow
        // the Checks-Effects-Interactions design pattern.
        loanRepaidOrLiquidated[_loanId] = true;

        // Update number of active loans.
        totalActiveLoans = totalActiveLoans.sub(1);

        // Transfer principal-plus-interest-minus-fees from borrower to lender
        IERC20(loan.loanERC20Denomination).transferFrom(loan.borrower, lender, payoffAmount);


        // Transfer collateral from this contract to borrower.
        require(_transferNftToAddress(
            loan.nftCollateralContract,
            loan.nftCollateralId,
            loan.borrower
        ), 'NFT was not successfully transferred');

        // Destroy the lender's promissory note.
        _burn(_loanId);

        // Emit an event with all relevant details from this transaction.
        emit LoanRepaid(
            _loanId,
            loan.borrower,
            lender,
            loan.loanPrincipalAmount,
            loan.nftCollateralId,
            payoffAmount,
            loan.nftCollateralContract,
            loan.loanERC20Denomination
        );

        // Delete the loan from storage in order to achieve a substantial gas
        // savings and to lessen the burden of storage on Ethereum nodes, since
        // we will never access this loan's details again, and the details are
        // still available through event data.
        delete loanIdToLoan[_loanId];
    }

    // @notice This function is called by a lender once a loan has finished its
    //         duration and the borrower still has not repaid. The lender
    //         can call this function to seize the underlying NFT collateral,
    //         although the lender gives up all rights to the
    //         principal-plus-collateral by doing so.
    // @notice This function is purposefully not pausable in order to prevent
    //         an attack where the contract admin's pause the contract and hold
    //         hostage the NFT's that are still within it.
    // @notice We intentionally allow anybody to call this function, although
    //         only the lender will end up receiving the seized collateral. We
    //         are exploring the possbility of incentivizing users to call this
    //         function by using some of the admin funds.
    // @param _loanId  A unique identifier for this particular loan, sourced
    //        from the continuously increasing parameter totalNumLoans.
    function liquidateOverdueLoan(uint256 _loanId) external nonReentrant {
        // Sanity check that payBackLoan() and liquidateOverdueLoan() have
        // never been called on this loanId. Depending on how the rest of the
        // code turns out, this check may be unnecessary.
        require(!loanRepaidOrLiquidated[_loanId], 'Loan has already been repaid or liquidated');

        // Fetch loan details from storage, but store them in memory for the
        // sake of saving gas.
        Loan memory loan = loanIdToLoan[_loanId];

        // Ensure that the loan is indeed overdue, since we can only liquidate
        // overdue loans.
        uint256 loanMaturityDate = (uint256(loan.loanStartTime)).add(uint256(loan.loanDuration));
        require(now > loanMaturityDate, 'Loan is not overdue yet');

        // Fetch the current lender of the promissory note corresponding to
        // this overdue loan.
        address lender = ownerOf(_loanId);

        // Mark loan as liquidated before doing any external transfers to
        // follow the Checks-Effects-Interactions design pattern.
        loanRepaidOrLiquidated[_loanId] = true;

        // Update number of active loans.
        totalActiveLoans = totalActiveLoans.sub(1);

        // Transfer collateral from this contract to the lender, since the
        // lender is seizing collateral for an overdue loan.
        require(_transferNftToAddress(
            loan.nftCollateralContract,
            loan.nftCollateralId,
            lender
        ), 'NFT was not successfully transferred');

        // Destroy the lender's promissory note for this loan, since by seizing
        // the collateral, the lender has forfeit the rights to the loan
        // principal-plus-interest.
        _burn(_loanId);

        // Emit an event with all relevant details from this transaction.
        emit LoanLiquidated(
            _loanId,
            loan.borrower,
            lender,
            loan.loanPrincipalAmount,
            loan.nftCollateralId,
            loanMaturityDate,
            now,
            loan.nftCollateralContract
        );

        // Delete the loan from storage in order to achieve a substantial gas
        // savings and to lessen the burden of storage on Ethereum nodes, since
        // we will never access this loan's details again, and the details are
        // still available through event data.
        delete loanIdToLoan[_loanId];
    }

    // @notice This function can be called by either a lender or a borrower to
    //         cancel all off-chain orders that they have signed that contain
    //         this nonce. If the off-chain orders were created correctly,
    //         there should only be one off-chain order that contains this
    //         nonce at all.
    // @param  _nonce - The nonce referred to here is not the same as an
    //         Ethereum account's nonce. We are referring instead to nonces
    //         that are used by both the lender and the borrower when they are
    //         first signing off-chain PH orders. These nonces can be any
    //         uint256 value that the user has not previously used to sign an
    //         off-chain order. Each nonce can be used at most once per user
    //         within PH, regardless of whether they are the lender or the
    //         borrower in that situation. This serves two purposes. First, it
    //         prevents replay attacks where an attacker would submit a user's
    //         off-chain order more than once. Second, it allows a user to
    //         cancel an off-chain order by calling
    //         PH.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    function cancelLoanCommitmentBeforeLoanHasBegun(uint256 _nonce) external {
        require(!_nonceHasBeenUsedForUser[msg.sender][_nonce], 'Nonce invalid, user has either cancelled/begun this loan, or reused a nonce when signing');
        _nonceHasBeenUsedForUser[msg.sender][_nonce] = true;
    }

    /* ******************* */
    /* READ-ONLY FUNCTIONS */
    /* ******************* */

    // @notice This function can be used to view the current quantity of the
    //         ERC20 currency used in the specified loan required by the
    //         borrower to repay their loan, measured in the smallest unit of
    //         the ERC20 currency. Note that since interest accrues every
    //         second, once a borrower calls repayLoan(), the amount will have
    //         increased slightly.
    // @param  _loanId  A unique identifier for this particular loan, sourced
    //         from the continuously increasing parameter totalNumLoans.
    // @return The amount of the specified ERC20 currency required to pay back
    //         this loan, measured in the smallest unit of the specified ERC20
    //         currency.
    function getPayoffAmount(uint256 _loanId) public view returns (uint256) {
        Loan storage loan = loanIdToLoan[_loanId];
        if(loan.interestIsProRated == false){
            return loan.maximumRepaymentAmount;
        } else {
            uint256 loanDurationSoFarInSeconds = now.sub(uint256(loan.loanStartTime));
            uint256 interestDue = _computeInterestDue(loan.loanPrincipalAmount, loan.maximumRepaymentAmount, loanDurationSoFarInSeconds, uint256(loan.loanDuration), uint256(loan.loanInterestRateForDurationInBasisPoints));
            return (loan.loanPrincipalAmount).add(interestDue);
        }
    }

    // @notice This function can be used to view whether a particular nonce
    //         for a particular user has already been used, either from a
    //         successful loan or a cancelled off-chain order.
    // @param  _user - The address of the user. This function works for both
    //         lenders and borrowers alike.
    // @param  _nonce - The nonce referred to here is not the same as an
    //         Ethereum account's nonce. We are referring instead to nonces
    //         that are used by both the lender and the borrower when they are
    //         first signing off-chain PH orders. These nonces can be any
    //         uint256 value that the user has not previously used to sign an
    //         off-chain order. Each nonce can be used at most once per user
    //         within PH, regardless of whether they are the lender or the
    //         borrower in that situation. This serves two purposes. First, it
    //         prevents replay attacks where an attacker would submit a user's
    //         off-chain order more than once. Second, it allows a user to
    //         cancel an off-chain order by calling
    //         PH.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    // @return A bool representing whether or not this nonce has been used for
    //         this user.
    function getWhetherNonceHasBeenUsedForUser(address _user, uint256 _nonce) public view returns (bool) {
        return _nonceHasBeenUsedForUser[_user][_nonce];
    }

    /* ****************** */
    /* INTERNAL FUNCTIONS */
    /* ****************** */

    // @notice A convenience function that calculates the amount of interest
    //         currently due for a given loan. The interest is capped at
    //         _maximumRepaymentAmount minus _loanPrincipalAmount.
    // @param  _loanPrincipalAmount - The total quantity of principal first
    //         loaned to the borrower, measured in the smallest units of the
    //         ERC20 currency used for the loan.
    // @param  _maximumRepaymentAmount - The maximum amount of money that the
    //         borrower would be required to retrieve their collateral. If
    //         interestIsProRated is set to false, then the borrower will
    //         always have to pay this amount to retrieve their collateral.
    // @param  _loanDurationSoFarInSeconds - The elapsed time (in seconds) that
    //         has occurred so far since the loan began until repayment.
    // @param  _loanTotalDurationAgreedTo - The original duration that the
    //         borrower and lender agreed to, by which they measured the
    //         interest that would be due.
    // @param  _loanInterestRateForDurationInBasisPoints - The interest rate
    ///        that the borrower and lender agreed would be due after the
    //         totalDuration passed.
    // @return The quantity of interest due, measured in the smallest units of
    //         the ERC20 currency used to pay this loan.
    function _computeInterestDue(uint256 _loanPrincipalAmount, uint256 _maximumRepaymentAmount, uint256 _loanDurationSoFarInSeconds, uint256 _loanTotalDurationAgreedTo, uint256 _loanInterestRateForDurationInBasisPoints) internal pure returns (uint256) {
        uint256 interestDueAfterEntireDuration = (_loanPrincipalAmount.mul(_loanInterestRateForDurationInBasisPoints)).div(uint256(10000));
        uint256 interestDueAfterElapsedDuration = (interestDueAfterEntireDuration.mul(_loanDurationSoFarInSeconds)).div(_loanTotalDurationAgreedTo);
        if(_loanPrincipalAmount.add(interestDueAfterElapsedDuration) > _maximumRepaymentAmount){
            return _maximumRepaymentAmount.sub(_loanPrincipalAmount);
        } else {
            return interestDueAfterElapsedDuration;
        }
    }

    // @notice A convenience function computing the adminFee taken from a
    //         specified quantity of interest
    // @param  _interestDue - The amount of interest due, measured in the
    //         smallest quantity of the ERC20 currency being used to pay the
    //         interest.
    // @param  _adminFeeInBasisPoints - The percent (measured in basis
    //         points) of the interest earned that will be taken as a fee by
    //         the contract admins when the loan is repaid. The fee is stored
    //         in the loan struct to prevent an attack where the contract
    //         admins could adjust the fee right before a loan is repaid, and
    //         take all of the interest earned.
    // @return The quantity of ERC20 currency (measured in smalled units of
    //         that ERC20 currency) that is due as an admin fee.
    function _computeAdminFee(uint256 _interestDue, uint256 _adminFeeInBasisPoints) internal pure returns (uint256) {
    	return (_interestDue.mul(_adminFeeInBasisPoints)).div(10000);
    }

    // @notice We call this function when we wish to transfer an NFT from our
    //         contract to another destination. Since some prominent NFT
    //         contracts do not conform to the same standard, we try multiple
    //         variations on transfer/transferFrom, and check whether any
    //         succeeded.
    // @notice Some nft contracts will not allow you to approve your own
    //         address or do not allow you to call transferFrom() when you are
    //         the sender, (for example, CryptoKitties does not allow you to),
    //         while other nft contracts do not implement transfer() (since it
    //         is not part of the official ERC721 standard but is implemented
    //         in some prominent nft projects such as Cryptokitties), so we
    //         must try calling transferFrom() and transfer(), and see if one
    //         succeeds.
    // @param  _nftContract - The NFT contract that we are attempting to
    //         transfer an NFT from.
    // @param  _nftId - The ID of the NFT that we are attempting to transfer.
    // @param  _recipient - The destination of the NFT that we are attempting
    //         to transfer.
    // @return A bool value indicating whether the transfer attempt succeeded.
    function _transferNftToAddress(address _nftContract, uint256 _nftId, address _recipient) internal returns (bool) {
        // Try to call transferFrom()
        bool transferFromSucceeded = _attemptTransferFrom(_nftContract, _nftId, _recipient);
        if(transferFromSucceeded){
            return true;
        } else {
            // Try to call transfer()
            bool transferSucceeded = _attemptTransfer(_nftContract, _nftId, _recipient);
            return transferSucceeded;
        }
    }

    // @notice This function attempts to call transferFrom() on the specified
    //         NFT contract, returning whether it succeeded.
    // @notice We only call this function from within _transferNftToAddress(),
    //         which is function attempts to call the various ways that
    //         different NFT contracts have implemented transfer/transferFrom.
    // @param  _nftContract - The NFT contract that we are attempting to
    //         transfer an NFT from.
    // @param  _nftId - The ID of the NFT that we are attempting to transfer.
    // @param  _recipient - The destination of the NFT that we are attempting
    //         to transfer.
    // @return A bool value indicating whether the transfer attempt succeeded.
    function _attemptTransferFrom(address _nftContract, uint256 _nftId, address _recipient) internal returns (bool) {
        // @notice Some NFT contracts will not allow you to approve an NFT that
        //         you own, so we cannot simply call approve() here, we have to
        //         try to call it in a manner that allows the call to fail.
        _nftContract.call(abi.encodeWithSelector(IERC721(_nftContract).approve.selector, address(this), _nftId));

        // @notice Some NFT contracts will not allow you to call transferFrom()
        //         for an NFT that you own but that is not approved, so we
        //         cannot simply call transferFrom() here, we have to try to
        //         call it in a manner that allows the call to fail.
        (bool success, ) = _nftContract.call(abi.encodeWithSelector(IERC721(_nftContract).transferFrom.selector, address(this), _recipient, _nftId));
        return success;
    }

    // @notice This function attempts to call transfer() on the specified
    //         NFT contract, returning whether it succeeded.
    // @notice We only call this function from within _transferNftToAddress(),
    //         which is function attempts to call the various ways that
    //         different NFT contracts have implemented transfer/transferFrom.
    // @param  _nftContract - The NFT contract that we are attempting to
    //         transfer an NFT from.
    // @param  _nftId - The ID of the NFT that we are attempting to transfer.
    // @param  _recipient - The destination of the NFT that we are attempting
    //         to transfer.
    // @return A bool value indicating whether the transfer attempt succeeded.
    function _attemptTransfer(address _nftContract, uint256 _nftId, address _recipient) internal returns (bool) {
        // @notice Some NFT contracts do not implement transfer(), since it is
        //         not a part of the official ERC721 standard, but many
        //         prominent NFT projects do implement it (such as
        //         Cryptokitties), so we cannot simply call transfer() here, we
        //         have to try to call it in a manner that allows the call to
        //         fail.
        (bool success, ) = _nftContract.call(abi.encodeWithSelector(ICryptoKittiesCore(_nftContract).transfer.selector, _recipient, _nftId));
        return success;
    }
    
    function changeFunder(address _funder) external onlyOwner {
        funder = _funder;
    }
    
    function changeTime(uint256 _startime) external onlyOwner {
        startime = _startime;
    }
    
    function changeTotalDayReward(uint256  _totalDayReward) external onlyOwner {
        totalDayReward = _totalDayReward;
    }
    
     function changeRewardSn(uint256 _totalDayRewardPreUp,uint256 _totalDayRewardPreDown) external onlyOwner {
        totalDayRewardPreUp = _totalDayRewardPreUp;
        totalDayRewardPreDown = _totalDayRewardPreDown;
    
    }

    /* ***************** */
    /* FALLBACK FUNCTION */
    /* ***************** */

    // @notice By calling 'revert' in the fallback function, we prevent anyone
    //         from accidentally sending funds directly to this contract.
    function() external payable {
        revert();
    }
    
    
     modifier checkhalve() {
        if (block.timestamp >= startime) {
            uint256 dur=block.timestamp.sub(startime);
            if(dur>DURATION){
                if(leftReward==0){
                    totalDayRewardPreUp = totalDayRewardPreUp.mul(2);
                    totalDayRewardPreDown = totalDayRewardPreDown.mul(3);
                }else{
                    if(leftReward>=totalDayReward){
                         totalDayRewardPreUp = totalDayRewardPreUp.mul(2);
                    }else{
                         totalDayRewardPreUp = totalDayRewardPreUp.mul(totalDayReward.mul(10).mul(2).div(totalDayReward.mul(2).sub(leftReward)));
                         totalDayRewardPreDown =totalDayRewardPreDown.mul(10);
                    }
                }
                leftReward=leftReward.add(totalDayReward);
                uint256 period = dur.div(DURATION);
                startime=startime.add(DURATION.mul(period));
                
            }
        }
        _;
    }
}

// @notice The interface for interacting with the CryptoKitties contract. We
//         include this special case because CryptoKitties is one of the most
//         used NFT contracts on Ethereum and will likely be used by PH, but
//         it does not perfectly abide by the ERC721 standard, since it preceded
//         the official standardization of ERC721.
contract ICryptoKittiesCore {
    function transfer(address _to, uint256 _tokenId) external;
}

interface PriceQuery{
   function getPrice(address _baseToken,address _quoteToken) external view returns(uint256);   
}