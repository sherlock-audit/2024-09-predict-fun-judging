# Issue M-1: A borrower can not repay to a USDC blacklisted lender 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/85 

The protocol has acknowledged this issue.

## Found by 
000000, 0rpse, 0xnbvc, GGONE, PUSH0, Pheonix, SyncCode2017, bughuntoor, iamnmt, kennedy1030, t.aksoy
### Summary

A borrower transfers `LOAN_TOKEN` directly to a lender when repaying their loan will cause the loan can not to be repaid when the lender is blacklisted by the `LOAN_TOKEN`.

### Root Cause

A borrower repays their loan by transferring `LOAN_TOKEN` directly to a  lender

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L470

```solidity
    function repay(uint256 loanId) external nonReentrant {
        Loan storage loan = loans[loanId];

        _assertAuthorizedCaller(loan.borrower);

        LoanStatus status = loan.status;
        if (status != LoanStatus.Active) {
            if (status != LoanStatus.Called) {
                revert InvalidLoanStatus();
            }
        }

        uint256 debt = _calculateDebt(loan.loanAmount, loan.interestRatePerSecond, _calculateLoanTimeElapsed(loan));

        loan.status = LoanStatus.Repaid;

>>      LOAN_TOKEN.safeTransferFrom(msg.sender, loan.lender, debt);
        CTF.safeTransferFrom(address(this), msg.sender, loan.positionId, loan.collateralAmount, "");

        emit LoanRepaid(loanId, debt);
    }
```

When `LOAN_TOKEN` is `USDC`, and the lender is blacklisted, the borrower can not transfer `USDC` to repay the lender.

### Internal pre-conditions

1. `LOAN_TOKEN` is `USDC`
2. The borrower has borrowed from the lender before the lender is blacklisted by `USDC`.

### External pre-conditions

The lender is blacklisted by `USDC`

### Attack Path

1. The borrower borrows from the lender
2. The lender is blacklisted by `USDC`
3. The borrower can not repay the lender

### Impact

1. The borrower can not repay their loan
2. The borrower can not get their collateral tokens (ERC1155) back
3. When the loan is matured, the lender can call the loan, and then seize all the collateral tokens (Note that, since the new lender also has to transfer `USDC` to the old lender, the auction functionality will not work, and the lender will guarantee to seize all the collateral tokens)

### PoC

_No response_

### Mitigation

Implement a pushing method for repaying a loan:
1. The borrower repays a loan by transferring the `LOAN_TOKEN` to the `PredictDotLoan` contract, and the loan amounts are credited to the lender.
2. The lender claims the loan amounts back from the `PredictDotLoan` contract.

# Issue M-2: Collateral can already be seized even when negRiskMarket is not fully resolved 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/113 

## Found by 
PUSH0
### Summary

NegRiskMarket has a two step verification process, in order to ensure reported outcomes are correct.
First the UMA oracle has the possibility to flag the answer and after this there is a period of time in which the negRiskAdapterOperator can flag the result.

View following code for negRiskOperator: [NegRiskOperator.sol](https://github.com/Polymarket/neg-risk-ctf-adapter/blob/main/src/NegRiskOperator.sol#L199C14-L202)
View following code for UMA report: [UmaCtfAdapter.sol](https://github.com/Polymarket/uma-ctf-adapter/blob/main/src/UmaCtfAdapter.sol#L415)

The negRiskOperator can still change the answer in case he deems it to be incorrect, even after the UMA oracle has reported a valid outcome.

This leads to following problem:
Currently the loan can be seized even if the negRiskAdapterOperator has flagged the result / the result is not yet determined.

In case the answer changes, it will lead to loss of collateral for the borrower.

### Root Cause

Currently the _isQuestionPriceAvailable function checks if the UMA oracle OR the Market is determined.
In case the UMA oracle returns a result, but this result is flagged and the market is not determined yet, the function will return true regardless.

```solidity
function _isQuestionPriceAvailable(
        QuestionType questionType,
        bytes32 questionId
    ) private view returns (bool isAvailable) {
        if (questionType == QuestionType.Binary) {
            (isAvailable, ) = _isBinaryOutcomeQuestionPriceAvailable(UMA_CTF_ADAPTER, questionId);
        } else {
            (isAvailable, ) = _isBinaryOutcomeQuestionPriceAvailable(NEG_RISK_UMA_CTF_ADAPTER, questionId);
            isAvailable = isAvailable || _isNegRiskMarketDetermined(questionId);
        }
    }
```
https://github.com/sherlock-audit/2024-09-predict-fun/blob/main/predict-dot-loan/contracts/PredictDotLoan.sol#L1496C5-L1507C1

### Internal pre-conditions

1. Lender creates loan on difficult market
2. The loan time ends and it becomes sizable 

### External pre-conditions

1. UMA Oracle returns an Answer
2. The UMA Oracles answers gets flagged / changed by the negRiskAdapterOperator.

### Attack Path

1. Create loan on difficult market that ends shortly after the market resolves
2. Take unrightfully collateral in case outcome changes 

### Impact

Lender can take borrowers collateral even if the answer has not fully resolved. Breaking invariant and leading to loss of funds. 

### Mitigation

It should be sufficient to check only _isNegRiskMarketDetermined(questionId).
From our research it can only return true in case the UMA oracle and the negRiskAdapter are correctly resolved.



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/PredictDotFun/predict-dot-loan/pull/45


# Issue M-3: Using wrong format of `questionId` for `NegRiskCtfAdapter` leads to loan operations on resolved multi-outcome markets 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/119 

## Found by 
kuprum
### Summary

`PredictDotLoan` contract aims at preventing operations with loans as soon as underlying binary questions or multi-outcome markets become resolved. Unfortunately the determination of whether the multi-outcome markets are resolved is implemented incorrectly.

The problem is that though the format of `questionId`s employed in `UmaCtfAdapter` and `NegRiskAdapter` are different, they are treated as the same in `PredictDotLoan`; as a result of this misinterpretation, the request [_isNegRiskMarketDetermined(bytes32 questionId)](https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L1480-L1482) will always return `false`. This will lead to treating multi-outcome markets as unresolved, and thus to a guaranteed loss of funds: e.g. giving a loan to the borrow proposal for a position which is guaranteed to resolve to 0.

### Root Cause

As outlined in the [documentation for Polymarket Multi-Outcome Markets](https://github.com/Polymarket/neg-risk-ctf-adapter/blob/e206dd2ed5aa24cf1f86990b875c6b1577be25e2/README.md):

> The NegRiskOperator and NegRiskAdapter are designed to be used with the [UmaCtfAdapter](https://github.com/Polymarket/uma-ctf-adapter), or any oracle with the same interface. A dedicated UmaCtfAdapter will need to be deployed with the UmaCtfAdapter's `ctf` set to the address of the NegRiskAdapter, and the NegRiskOperator's `oracle` set to the address of the UmaCtfAdapter.
>
> In order to prepare a question for a market using the NegRiskOperator, the question must be initialized on the UmaCtfAdapter first. Then, the question may be prepared on the NegRiskOperator where the `_requestId` parameter is the `questionID` returned by the UmaCtfAdapter.

As can be seen, `questionId` as employed in `UmaCtfAdapter` becomes `_requestId` in `NegRiskOperator`, which generates its own `questionId`, in another format. Concretely:

- `UmaCtfAdapter`'s `questionId` is generated in [UmaCtfAdapter::initialize](https://github.com/Polymarket/uma-ctf-adapter/blob/7f7dccd745023f908ae2c43717ae906b3d16872d/src/UmaCtfAdapter.sol#L87-L115) as follows:

   ```solidity
    bytes memory data = AncillaryDataLib._appendAncillaryData(msg.sender, ancillaryData);
    if (ancillaryData.length == 0 || data.length > MAX_ANCILLARY_DATA) revert InvalidAncillaryData();

    questionID = keccak256(data);
   ```
   Thus, this `questionId` is obtained by `keccak256` of initialization data.

- `NegRiskAdapter`'s `questionId` is generated via [NegRiskOperator::prepareQuestion](https://github.com/Polymarket/neg-risk-ctf-adapter/blob/e206dd2ed5aa24cf1f86990b875c6b1577be25e2/src/NegRiskOperator.sol#L107-L129):

   ```solidity
   function prepareQuestion(bytes32 _marketId, bytes calldata _data, bytes32 _requestId)
   ```
   which then routes to [MarketDataManager::_prepareQuestion](https://github.com/Polymarket/neg-risk-ctf-adapter/blob/e206dd2ed5aa24cf1f86990b875c6b1577be25e2/src/modules/MarketDataManager.sol#L74-L84):

   ```solidity
    function _prepareQuestion(bytes32 _marketId) internal returns (bytes32 questionId, uint256 index) {
        MarketData md = marketData[_marketId];
        address oracle = marketData[_marketId].oracle();

        if (oracle == address(0)) revert MarketNotPrepared();
        if (oracle != msg.sender) revert OnlyOracle();

        index = md.questionCount();
        questionId = NegRiskIdLib.getQuestionId(_marketId, uint8(index));
        marketData[_marketId] = md.incrementQuestionCount();
    }
   ```
   As can be seen, the latter `questionId` is obtained by merging `marketId` (248 bits) and `index` (8 bits).

Despite this discrepancy in formats, the  `questionId` from `UmaCtfAdapter` is employed in `PredictDotLoan` for requesting the state of the market from `NegRiskAdapter` in [_assertQuestionPriceUnavailable](https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L1468-L1482):

```solidity
function _assertQuestionPriceUnavailable(QuestionType questionType, bytes32 questionId) private view {
    if (questionType == QuestionType.Binary) {
        _assertBinaryOutcomeQuestionPriceUnavailable(UMA_CTF_ADAPTER, questionId);
    } else {
        if (_isNegRiskMarketDetermined(questionId)) {
            revert MarketResolved();
        }
        _assertBinaryOutcomeQuestionPriceUnavailable(NEG_RISK_UMA_CTF_ADAPTER, questionId);
    }
}

function _isNegRiskMarketDetermined(bytes32 questionId) private view returns (bool isDetermined) {
@>>    isDetermined = NEG_RISK_ADAPTER.getDetermined(NegRiskIdLib.getMarketId(questionId));
}
```

`NegRiskAdapter`'s `getDetermined` is implemented [as follows](https://github.com/Polymarket/neg-risk-ctf-adapter/blob/e206dd2ed5aa24cf1f86990b875c6b1577be25e2/src/modules/MarketDataManager.sol#L38-L40):

```solidity
function getDetermined(bytes32 _marketId) external view returns (bool) {
    return marketData[_marketId].determined();
}

function determined(MarketData _data) internal pure returns (bool) {
    return MarketData.unwrap(_data)[1] == 0x00 ? false : true;
}
```

As `NegRiskIdLib.getMarketId` simply masks the last 8 bits away _from `questionId` in the wrong format_, and the above code simply reads the data from a mapping, combined it means that `getDetermined` will always return `false` as it will read data from an uninitialized mapping entry.

### Impact

Guaranteed loss of funds: when a multi-outcome market gets resolved (e.g. we know that candidate A won elections), then all other positions (for candidates B, C, D) automatically become worthless. But if `PredictDotLoan` still treats the multi-outcome market as unresolved, this allows a multitude of exploits: e.g. grabbing an open loan proposal, and providing as collateral tokens for candidate B; or providing a loan for a still open borrow proposal for candidate A, and potentially seizing much more funds than the provided loan amount.


### Mitigation

Apply the necessary missing step of indirection: 
- Read the public [questionIds](https://github.com/Polymarket/neg-risk-ctf-adapter/blob/e206dd2ed5aa24cf1f86990b875c6b1577be25e2/src/NegRiskOperator.sol#L52) mapping from `NegRiskOperator`, using `UmaCtfAdapter`'s `questionId` as `_requestId`:

   ```solidity
   mapping(bytes32 _requestId => bytes32) public questionIds;
   ```
- Apply this value to request the market state in function [_isNegRiskMarketDetermined](https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L1480-L1482).



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/PredictDotFun/predict-dot-loan/pull/43


# Issue M-4: The last lender of a partially fulfilled borrow request might have a significantly higher collateral ratio than the collateral ratio specified in the borrow request 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/125 

## Found by 
056Security, PUSH0, bughuntoor, cryptomoon, dany.armstrong90, debugging3, eeyore, iamnmt, kennedy1030, tobi0x18
### Summary

The last lender of a partially fulfilled borrow request might have a significantly higher collateral ratio than the collateral ratio specified in the borrow request.

### Root Cause

In `_acceptOffer`, the `collateralAmountRequired` is the leftover collateral when the borrow request is fully filled

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L983

```solidity
    function _calculateCollateralAmountRequired(
        Proposal calldata proposal,
        Fulfillment storage fulfillment,
        uint256 fulfillAmount
    ) private view returns (uint256 collateralAmountRequired) {
        if (fulfillment.loanAmount + fulfillAmount == proposal.loanAmount) {
>>          collateralAmountRequired = proposal.collateralAmount - fulfillment.collateralAmount;
        } else {
            collateralAmountRequired = (proposal.collateralAmount * fulfillAmount) / proposal.loanAmount;
        }
    }
```

The borrower can use `matchProposals` to match their borrow request to a better loan offer, which has a lower collateral ratio than the ratio of the borrow request

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L351-L356

```solidity
        if (
            borrowRequest.collateralAmount * loanOffer.loanAmount <
            borrowRequest.loanAmount * loanOffer.collateralAmount
        ) {
            revert UnacceptableCollateralizationRatio();
        }
```

then the collateral ratio of the loan is the collateral ratio of the loan offer

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L395-L399

If the borrower has used their borrow request to match with the lower collateral ratio loan offer, then the last lender that fully accepts the borrow request will have a significantly higher collateral ratio than the collateral ratio specified in the borrow request.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. Alice signs a borrow request that has `collateralAmount = 20 ether`, and `loanAmount = 10 ether` (collateral ratio = 200%)
2. Bob signs a loan offer that has `collateralAmount = 5 ether`, and `loanAmount = 5 ether` (collateral ratio = 100%)
3. Since Bob's loan offer has a lower collateral ratio than her borrow request, the loan offer is better for her. Alice matches Bob's loan offer against her. Current states:
   - `fulfillment.collateralAmount = 15 ether`
   - `fulfillment.loanAmount = 5  ether`
4. Cindy fully accepts Alice's borrow request, and Cindy benefits from a loan with high collateral ratio (15 ether / 5 ether = 300%)

We believe the loan should only have a collateral ratio lower than or equal to 200%.

### Impact

- The last lender (Cindy) might have a significantly higher collateral ratio than the collateral ratio specified in the borrow request
- The borrower (Alice) will have a loan that has a higher collateral ratio than expected. 


### PoC

Add a view function in `PredictDotLoan` to check the collateral ratio of a loan

```solidity
contract PredictDotLoan is AccessControl, EIP712, ERC1155Holder, IPredictDotLoan, Pausable, ReentrancyGuard {
    ...
    function getLoanCollateralRatio(uint256 loanId) public view returns (uint256) {
        IPredictDotLoan.Loan memory loan = loans[loanId];
        return loan.collateralAmount * 1 ether / loan.loanAmount;
    }
}
```

Run command: `forge test --match-path test/foundry/PoC.t.sol -vv`

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import {IPredictDotLoan} from "../../contracts/interfaces/IPredictDotLoan.sol";
import {TestHelpers} from "./TestHelpers.sol";
import {console} from "forge-std/Test.sol";

contract PoC is TestHelpers {
    uint256 aliceKey = 1;
    uint256 bobKey = 2;

    address alice = vm.addr(aliceKey);
    address bob = vm.addr(bobKey);
    address cindy = makeAddr('cindy');

    function setUp() public {
        _deploy();

        vm.prank(alice);
        mockCTF.setApprovalForAll(address(predictDotLoan), true);
        _mintCTF(alice);

        mockERC20.mint(bob, LOAN_AMOUNT);
        vm.prank(bob);
        mockERC20.approve(address(predictDotLoan), LOAN_AMOUNT);

        mockERC20.mint(cindy, LOAN_AMOUNT);
        vm.prank(cindy);
        mockERC20.approve(address(predictDotLoan), LOAN_AMOUNT);
    }

    function test_PoC() public {
        // Collateral ratio: 20 / 10 = 200%
        IPredictDotLoan.Proposal memory borrowRequest = _generateBorrowRequest(
            IPredictDotLoan.QuestionType.Binary,
            alice,
            aliceKey,
            20 ether,
            10 ether
        );

        // Collateral ratio: 5 / 5 = 100%
        IPredictDotLoan.Proposal memory loanOffer = _generateLoanOffer(
            IPredictDotLoan.QuestionType.Binary,
            bob,
            bobKey,
            5 ether,
            5 ether
        );

        predictDotLoan.matchProposals(borrowRequest, loanOffer);

        vm.prank(cindy);
        predictDotLoan.acceptBorrowRequest(borrowRequest, 5 ether);

        console.log("First loan's collateral ratio: %e", predictDotLoan.getLoanCollateralRatio(1));
        console.log("Second loan's collateral ratio: %e", predictDotLoan.getLoanCollateralRatio(2));
    }

    function _generateBorrowRequest(
        IPredictDotLoan.QuestionType questionType,
        address from,
        uint256 privateKey,
        uint256 collateralAmount,
        uint256 loanAmount
    ) internal view returns (IPredictDotLoan.Proposal memory proposal) {
        proposal = _generateBaseProposal(questionType);
        proposal.collateralAmount = collateralAmount;
        proposal.loanAmount = loanAmount;
        proposal.from = from;
        proposal.proposalType = IPredictDotLoan.ProposalType.BorrowRequest;

        (, uint128 borrowingNonce) = predictDotLoan.nonces(from);
        proposal.nonce = borrowingNonce;

        proposal.signature = _signProposal(proposal, privateKey);
    }

    function _generateLoanOffer(
        IPredictDotLoan.QuestionType questionType,
        address from,
        uint256 privateKey,
        uint256 collateralAmount,
        uint256 loanAmount
    ) internal view returns (IPredictDotLoan.Proposal memory proposal) {
        proposal = _generateBaseProposal(questionType);
        proposal.collateralAmount = collateralAmount;
        proposal.loanAmount = loanAmount;
        proposal.from = from;
        proposal.proposalType = IPredictDotLoan.ProposalType.LoanOffer;

        (uint128 lendingNonce, ) = predictDotLoan.nonces(from);
        proposal.nonce = lendingNonce;

        proposal.signature = _signProposal(proposal, privateKey);
    }
}
```

Logs:
```bash
  First loan's collateral ratio: 1e18
  Second loan's collateral ratio: 3e18
```

### Mitigation

In `_calculateCollateralAmountRequired`, the `collateralAmountRequired` is the leftover collateral only when the leftover amounts are only a few weis.
```solidity
    function _calculateCollateralAmountRequired(
        Proposal calldata proposal,
        Fulfillment storage fulfillment,
        uint256 fulfillAmount
    ) private view returns (uint256 collateralAmountRequired) {
	collateralAmountRequired = (proposal.collateralAmount * fulfillAmount) / proposal.loanAmount;

	if (fulfillment.loanAmount + fulfillAmount == proposal.loanAmount && proposal.collateralAmount - fulfillment.collateralAmount - collateralAmountRequired < THRESHOLD) {
            collateralAmountRequired = proposal.collateralAmount - fulfillment.collateralAmount;
        } 
    }
```

`THRESHOLD` could be `10`.



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/PredictDotFun/predict-dot-loan/pull/32


# Issue M-5: An incorrect fee calculation may result in the application of two different fee rates 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/200 

## Found by 
000000, 0xNirix, bughuntoor, dany.armstrong90, iamnmt, kennedy1030, silver\_eth, t.aksoy, tobi0x18
### Summary

The protocol imposes a fee on each loan, calculated as a percentage of the loan amount. However, the usage of protocolFeeBasisPoints varies across different sections of the code.

### Root Cause

The `_acceptOrder()` and `matchProposals` functions use the following `_transferLoanAmountAndProtocolFee` function. 
The amount of fee are calculated as the percentage of the whole `loanAmount`.
https://github.com/sherlock-audit/2024-09-predict-fun/blob/main/predict-dot-loan/contracts/PredictDotLoan.sol#L889-L899
```solidity
    function _transferLoanAmountAndProtocolFee(
        address from,
        address to,
        uint256 loanAmount
    ) private returns (uint256 protocolFee) {
        protocolFee = (loanAmount * protocolFeeBasisPoints) / 10_000;
        LOAN_TOKEN.safeTransferFrom(from, to, loanAmount - protocolFee);
        if (protocolFee > 0) {
            LOAN_TOKEN.safeTransferFrom(from, protocolFeeRecipient, protocolFee);
        }
    }
```

The `refinace()`, `auction` and `acceptLoanOfferAndFillOrder` use the following function.
https://github.com/sherlock-audit/2024-09-predict-fun/blob/main/predict-dot-loan/contracts/PredictDotLoan.sol#L889-L899
```solidity
    function _transferLoanAmountAndProtocolFeeWithoutDeductingFromLoanAmount(
        address from,
        address to,
        uint256 loanAmount,
        uint256 protocolFee
    ) private {
        LOAN_TOKEN.safeTransferFrom(from, to, loanAmount);
        if (protocolFee > 0) {
            LOAN_TOKEN.safeTransferFrom(from, protocolFeeRecipient, protocolFee);
        }
    }
```
The `protocolFee` represents the percentage of the loan amount that is actually disbursed to the borrower.
```solidity
    protocolFee = (exchangeOrder.takerAmount * protocolFeeBasisPoints) / 10_000;
      [...]
    protocolFee = (debt * protocolFeeBasisPoints) / 10_000;
      [...]
```

In other words, the protocol employs two different formulas for calculating fees.

### Internal pre-conditions

protocolFeeBasisPoints = 200

### External pre-conditions

None

### Attack Path

Consider the following scenario:
- Alice called `acceptOffer()` with `loanAmount` as 10000. 
    protocolFee = 10000 * 200 / 10000 = 200.
    So, the amount actually given to Alice is 10000 - 200 = 9800.
- Bob called `acceptLoanOfferAndFillOrder()` with `exchangeOrder.takerAmount` as 9800.
    protocolFee = 9800 * 200 / 10000 = 196.

In the scenario described above, both Alice and Bob each receive 98,000 LOAN_TOKEN.
However, Alice pays 5 LOAN_TOKEN more than Bob does.

### Impact

The fee calculation mechanism operates in two distinct ways.

### PoC

### Mitigation

The fee calculation mechanism should be unified.



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/PredictDotFun/predict-dot-loan/pull/50


# Issue M-6: If Lender gets blacklisted for USDC it will DoS borrower from repaying, which will lock up the collateral CTF tokens. 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/214 

The protocol has acknowledged this issue.

## Found by 
valuevalk
## Summary
USDC has blacklist functionality. If the lender gets blacklisted, the borrower cannot repay the debt and get his collateral back.

## Vulnerability Detail

**Flow:**
- Borrower accepts loan offer and Lender transfers him the `LOAN_TOKEN`. `CTF_TOKEN` ( the collateral ) gets deposited into the `PredictDotLoan.sol` contract. Borrower believes his collateral is valuable, but needs more liquidity/capital.
- Lender gets blacklisted for USDC.
- Borrower wants to repay and get his valuable collateral back, however he can't because we use the "push-model" which is trying to transfer back the `LOAN_TOKEN` to the Lender in the same call.  The transaction fails. - [snippet](https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L470)
```solidity
    function repay(uint256 loanId) external nonReentrant {
        Loan storage loan = loans[loanId];
        _assertAuthorizedCaller(loan.borrower);
        LoanStatus status = loan.status;
        if (status != LoanStatus.Active) {
            if (status != LoanStatus.Called) {
                revert InvalidLoanStatus();
            }
        }
        uint256 debt = _calculateDebt(loan.loanAmount, loan.interestRatePerSecond, _calculateLoanTimeElapsed(loan));
        loan.status = LoanStatus.Repaid;

@>>        LOAN_TOKEN.safeTransferFrom(msg.sender, loan.lender, debt);

        CTF.safeTransferFrom(address(this), msg.sender, loan.positionId, loan.collateralAmount, "");
        emit LoanRepaid(loanId, debt);
    }
```    
- Borrower cannot regain his collateral and its locked in the `PredictDotLoan.sol` contract.

## Impact
Valuable collateral of the borrower is stuck in the `PredictDotLoan.sol` contract.

## Tool used

Manual Review

## Recommendation
Instead of using the push-model ( to directly push the funds that need to be withdrawn to the lender ), use the pull design pattern. This way the lender can withdraw the `LOAN_TOKEN` himself, without locking valuable ConditionalToken collateral which the borrower can't get back because of failing transfer due to blacklist.
If the lender gets blacklisted and can't withdraw `LOAN_TOKEN` its his fault.


# Issue M-7: Malicios user can block borrowers repay using blocklist in USDC 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/240 

The protocol has acknowledged this issue.

## Found by 
Sickurity
### Summary

According to the Contest Readme, the protocol is allowed to be used in other networks. In these networks, USDC, which has a blacklist function, will serve as the Loan token.

The repay function transfers LOAN_TOKEN from the borrower to the lender.

Thus, a malicious actor (lender) can manipulate the call of the repay function from the borrower, preventing them from repaying the debt in this transaction, which leads to an [increase in their debt](https://github.com/sherlock-audit/2024-09-predict-fun/blob/main/predict-dot-loan/contracts/PredictDotLoan.sol#L772C5-L773C20). 
```solidity
function repay(uint256 loanId) external nonReentrant {
        Loan storage loan = loans[loanId];

        _assertAuthorizedCaller(loan.borrower);

        LoanStatus status = loan.status;
        if (status != LoanStatus.Active) {
            if (status != LoanStatus.Called) {
                revert InvalidLoanStatus();
            }
        }

        uint256 debt = _calculateDebt(loan.loanAmount, loan.interestRatePerSecond, _calculateLoanTimeElapsed(loan));

        loan.status = LoanStatus.Repaid;

        LOAN_TOKEN.safeTransferFrom(msg.sender, loan.lender, debt);
        CTF.safeTransferFrom(address(this), msg.sender, loan.positionId, loan.collateralAmount, "");

        emit LoanRepaid(loanId, debt);
    }
 ```

### Root Cause

The Root Cause lies in the fact that the repay function transfers funds directly to the lender's address, which could potentially be malicious. In combination with USDC's blacklist functionality, this creates opportunities for this attack.

### Internal pre-conditions

_No response_

### External pre-conditions

The protocol must be deployed on a network other than Blast and use USDC as the LOAN token.

### Attack Path

The attacker issues a loan, after adding his address to the USDC blocklist, the user is unable to repay his loan until the attacker is able to invoke a call on the loan. After that, the interest that the user will pay for his loan will be maximised.

### Impact

In networks other than Blast, lenders can intentionally prevent borrowers from repaying loans, either forcing them into default or increasing interest rates.

An example of such an error, rated as high severity.

[1](https://solodit.xyz/issues/h-4-lender-force-loan-become-default-sherlock-cooler-cooler-git_)

However, since the main network for this protocol is Blast, and USDC will be used as the LOAN token in other networks, presumably, the severity is: medium.

### PoC

_No response_

### Mitigation

Use Solidity Withdrawal pattern

# Issue M-8: hashProposal uses wrong typeshash when hashing the encoded Proposal struct data 

Source: https://github.com/sherlock-audit/2024-09-predict-fun-judging/issues/266 

## Found by 
0xAadi, 0xShoonya, Ironsidesec, KiroBrejka, ZanyBonzy, h2134, infect3d, valuevalk
### Summary

`acceptLoanOfferAndFillOrder`, `_refinance`, `matchProposals` use `_assertValidSignature` which hashes proposal data and verifies the signature. But the hashed proposal type hash computation is wrong due to usage of `uint256 questionId` instead of `bytes32 questionId`

There are 2 impacts. So, even if one is acceptable/wrong, then the issue impact on another.
1. This will break the signature verification. 
2. And breaking the strict EIP712's compatibility (mentioned in readme) where atomic types should be the same as the data format in the struct. Mentioned in ` Definition of typed structured data ` section.

### Root Cause

Using `uint256 questionId`  instead of  `bytes32 questionId`  inside the type hash of `hashProposal()`


### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

Issue flow : 

1. look at line 50 below, the `questionId` is in bytes 32. And when hashing a proposal data, the type hash of proposal struct format should also use bytes32 for question id. But here its using uint256. Check on line 819 below.
2. Due to this, the type hash will be different result. look at the chisel example below. The hashes are different, so the signature hash is using wrong digest to verify the signature. Should have used bytes32 itself.

This breaks the EIP712 , where atomic types like uint, bytes1 to bytes32, address should be directly used. And only strings, bytes data are dynamic types, should be keccack hashed and then derive the type hash.

<img width="953" alt="image" src="https://github.com/user-attachments/assets/63d5d1d8-9b5d-4544-8acf-84e62110f1c1">

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/interfaces/IPredictDotLoan.sol#L50

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L817

```solidity
IPredictDotLoan.sol

45:     struct Proposal {
    ---- SNIP ----
49:         QuestionType questionType;
50:   >   bytes32 questionId;
51:         bool outcome;
52:         uint256 interestRatePerSecond;
    ---- SNIP ----
59:         uint256 protocolFeeBasisPoints;
60:     }


PredictDotLoan.sol

814:     function hashProposal(Proposal calldata proposal) public view returns (bytes32 digest) {
815:         digest = _hashTypedDataV4(
816:             keccak256(
817:                 abi.encode(
818:                     keccak256(
819:      >>>                "Proposal(address from,uint256 loanAmount,uint256 collateralAmount,uint8 questionType,uint256 questionId,bool outcome,uint256 interestRatePerSecond,uint256 duration,uint256 validUntil,uint256 salt,uint256 nonce,uint8 proposalType,uint256 protocolFeeBasisPoints)"
820:                     ),
    ---- SNIP ----
824:                     proposal.questionType,
825:                     proposal.questionId,
    ---- SNIP ----

834:                 )
835:             )
836:         );
837:     }
```

### Impact

2 impacts

1. due to wrong type hash computation leading to wrong digest validation in the signature validator, the signatures might fail.
2. breaking the EIP712 mentioned in `readme` where it strictly complains. The atomic types should not be hashed or converted to other types.

### PoC

_No response_

### Mitigation

https://github.com/sherlock-audit/2024-09-predict-fun/blob/41e70f9eed3f00dd29aba4038544150f5b35dccb/predict-dot-loan/contracts/PredictDotLoan.sol#L817

```diff
    function hashProposal(Proposal calldata proposal) public view returns (bytes32 digest) {
        digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                   keccak256(
                       "Proposal(address from,uint256 loanAmount,uint256 collateralAmount,uint8 questionType,
- uint256 questionId,
                       bool outcome,uint256 interestRatePerSecond,uint256 duration,uint256 validUntil,uint256 salt,uint256 nonce,uint8 proposalType,uint256 protocolFeeBasisPoints)"
                    ),
                    keccak256(
                        "Proposal(address from,uint256 loanAmount,uint256 collateralAmount,uint8 questionType,
+ bytes32 questionId,
                    bool outcome,uint256 interestRatePerSecond,uint256 duration,uint256 validUntil,uint256 salt,uint256 nonce,uint8 proposalType,uint256 protocolFeeBasisPoints)"
                    ),
                    proposal.from,
    ---- SNIP ----

                )
            )
        );
    }
```



## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/PredictDotFun/predict-dot-loan/pull/37


