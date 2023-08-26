// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.18;

import "./HelperContract.t.sol";
import {MockERC20WithBlackList} from "../mock/MockERC20WithBlackList.sol";
import {Distributor} from "../../src/Distributor.sol";
import {Proxy} from "../../src/Proxy.sol";
import {ProxyFactory} from "../../src/ProxyFactory.sol";
import {console} from "forge-std/console.sol";

contract MyTests is HelperContract {
    MockERC20WithBlackList public jpycv1;
    MockERC20WithBlackList public jpycv2;
    MockERC20WithBlackList public usdc;
    ProxyFactory public proxyFactory2;
    Proxy public proxy2;
    Distributor public distributor2;

    function setUp() public {
        // set up balances of each token belongs to each user
        if (block.chainid == 31337) {
            // deploy contracts
            jpycv1 = new MockERC20WithBlackList("JPYCv1", "JPYCv1");
            jpycv2 = new MockERC20WithBlackList("JPYCv2", "JPYCv2");
            usdc = new MockERC20WithBlackList("USDC", "USDC");

            // setting whitelisted tokens
            address[] memory tokens = new address[](3);
            tokens[0] = address(jpycv1);
            tokens[1] = address(jpycv2);
            tokens[2] = address(usdc);

            // deploying proxy factory
            proxyFactory2 = new ProxyFactory(tokens);

            // deploying distributor
            distributor2 = new Distributor(address(proxyFactory2), stadiumAddress);

            // deal ether
            vm.deal(factoryAdmin, STARTING_USER_BALANCE);
            vm.deal(sponsor, SMALL_STARTING_USER_BALANCE);
            vm.deal(organizer, SMALL_STARTING_USER_BALANCE);
            vm.deal(user1, SMALL_STARTING_USER_BALANCE);
            vm.deal(user2, SMALL_STARTING_USER_BALANCE);
            vm.deal(user3, SMALL_STARTING_USER_BALANCE);
            vm.deal(TEST_SIGNER, SMALL_STARTING_USER_BALANCE);

            // mint erc20 token
            MockERC20WithBlackList(address(jpycv1)).mint(sponsor, 100_000 ether); // 100k JPYCv1
            MockERC20WithBlackList(address(jpycv2)).mint(sponsor, 300_000 ether); // 300k JPYCv2
            MockERC20WithBlackList(address(usdc)).mint(sponsor, 10_000 ether); // 10k USDC
            MockERC20WithBlackList(address(jpycv1)).mint(organizer, 100_000 ether); // 100k JPYCv1
            MockERC20WithBlackList(address(jpycv2)).mint(organizer, 300_000 ether); // 300k JPYCv2
            MockERC20WithBlackList(address(usdc)).mint(organizer, 10_000 ether); // 10k USDC
            MockERC20WithBlackList(address(jpycv1)).mint(TEST_SIGNER, 100_000 ether); // 100k JPYCv1
            MockERC20WithBlackList(address(jpycv2)).mint(TEST_SIGNER, 300_000 ether); // 300k JPYCv2
            MockERC20WithBlackList(address(usdc)).mint(TEST_SIGNER, 10_000 ether); // 10k USDC
        }

        // labels
        vm.label(organizer, "organizer");
        vm.label(sponsor, "sponsor");
        vm.label(supporter, "supporter");
        vm.label(user1, "user1");
        vm.label(user2, "user2");
        vm.label(user3, "user3");
    }

    function getProxyAddress(bytes32 salt, address implementation) public view returns (address proxy) {
        bytes memory code = abi.encodePacked(type(Proxy).creationCode, uint256(uint160(implementation)));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(code)));
        proxy = address(uint160(uint256(hash)));
    }

    function testShouldBeAbleToSetContestUsingProxyFactory2() public {
        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
    }

    function testFailShouldNotBeAbleToTransferAmountToWinnersInCaseOfBlacklistedStadiumAddress() public {
        // checking if the token is whitelisted in proxyfactory
        assertEq(proxyFactory2.whitelistedTokens(address(jpycv2)), true);
        assertEq(proxyFactory2.whitelistedTokens(address(jpycv1)), true);
        assertEq(proxyFactory2.whitelistedTokens(address(usdc)), true);

        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor2)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));
        console.log(proxyFactory2.saltToCloseTime(salt));

        // set blacklisted stadium address
        MockERC20WithBlackList(address(jpycv1)).addToBlackList(stadiumAddress);
        MockERC20WithBlackList(address(jpycv2)).addToBlackList(stadiumAddress);
        MockERC20WithBlackList(address(usdc)).addToBlackList(stadiumAddress);

        // set tokens, winners, percentages
        address token = address(jpycv2);
        address[] memory winners = new address[](1);
        winners[0] = user1;
        uint256[] memory percentages = new uint256[](1);
        percentages[0] = 9500;

        // set data
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sending tokens to proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor2));
        vm.startPrank(sponsor);
        MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        vm.stopPrank();

        // distribute
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor2), data);
        vm.stopPrank();
    }

    function testShouldBeAbleToTransferAmountToWinnersInCaseOfNonBlacklistedStadiumAddress() public {
        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor2)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));
        console.log(proxyFactory2.saltToCloseTime(salt));
        console.log(closeTime);

        // getting the address of the proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor2));

        // set blacklisted stadium address
        // MockERC20WithBlackList(address(jpycv1)).addToBlackList(stadiumAddress);
        // MockERC20WithBlackList(address(jpycv2)).addToBlackList(stadiumAddress);
        // MockERC20WithBlackList(address(usdc)).addToBlackList(stadiumAddress);

        // set tokens, winners, percentages
        address token = address(jpycv2);
        address[] memory winners = new address[](1);
        winners[0] = user1;
        uint256[] memory percentages = new uint256[](1);
        percentages[0] = 9500;

        // set data
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sending tokens to proxy
        vm.startPrank(sponsor);
        MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        vm.stopPrank();

        // distribute
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor2), data);
        vm.stopPrank();
    }

    function testFailShouldRevertIfTheWinnerAddressIsBlackListed() public {
        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor2)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));
        console.log(proxyFactory2.saltToCloseTime(salt));
        console.log(closeTime);

        // getting the address of the proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor2));

        // set blacklisted user
        MockERC20WithBlackList(address(jpycv1)).addToBlackList(user1);
        MockERC20WithBlackList(address(jpycv2)).addToBlackList(user1);
        MockERC20WithBlackList(address(usdc)).addToBlackList(user1);

        // set tokens, winners, percentages
        address token = address(jpycv2);
        address[] memory winners = new address[](1);
        winners[0] = user1;
        uint256[] memory percentages = new uint256[](1);
        percentages[0] = 9500;

        // set data
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sending tokens to proxy
        vm.startPrank(sponsor);
        MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        vm.stopPrank();

        // distribute
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor2), data);
        vm.stopPrank();
    }

    function testDeployingDistributorWithSameFactoryAndStadiumAddressWillLockTheTokens() public {
        // deploying distributor
        Distributor distributor3 = new Distributor(address(proxyFactory2), address(proxyFactory2));

        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor3));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor3)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));

        // getting the address of the proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor3));

        // set tokens, winners, percentages
        address token = address(jpycv2);
        address[] memory winners = new address[](1);
        winners[0] = user1;
        uint256[] memory percentages = new uint256[](1);
        percentages[0] = 9500;

        // set data
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sending tokens to proxy
        vm.startPrank(sponsor);
        MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        vm.stopPrank();

        // distribute
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor3), data);
        vm.stopPrank();

        assertEq(MockERC20WithBlackList(token).balanceOf(address(proxyFactory2)), 500 ether);
    }

    function testFraudOrganizerCanTakeAllTheWinnersFunds() public {
        // organizer's balance before distribution
        address token = address(jpycv2);
        uint256 oldOrganizerBalance = MockERC20WithBlackList(token).balanceOf(organizer);

        // owner set's contest
        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor2)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));

        // getting the address of the proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor2));

        // organiser sets winners, percentages
        address[] memory winners = new address[](1);
        winners[0] = organizer;
        uint256[] memory percentages = new uint256[](1);
        percentages[0] = 9500;

        // organiser sets data to distribute
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sponsors sending tokens to the proxy (considering one of it could be organiser as well)
        vm.startPrank(sponsor);
        MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        vm.stopPrank();

        // organizer distributes funds by setting himself as a winner and gets all the tokens
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor2), data);
        vm.stopPrank();

        // organiser has the winning balance
        uint256 newOrganizerBalance = MockERC20WithBlackList(token).balanceOf(organizer);
        assertEq(newOrganizerBalance - oldOrganizerBalance, 9500 ether);
    }

    function testTheWinnersGetPaidLessAmountIfTheTokenPromisedIsNotUsedForPayment() public {
        // no need for test - will delete after submission. just to remember
    }

    function testShouldRevertWhenFundsAreZero() public {
        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor2)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));
        console.log(proxyFactory2.saltToCloseTime(salt));
        console.log(closeTime);

        // getting the address of the proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor2));

        // set tokens, winners, percentages
        address token = address(jpycv2);
        address[] memory winners = new address[](1);
        winners[0] = user1;
        uint256[] memory percentages = new uint256[](1);
        percentages[0] = 9500;

        // set data
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sending tokens to proxy
        // vm.startPrank(sponsor);
        // MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        // vm.stopPrank();

        // distribute
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        vm.expectRevert(ProxyFactory.ProxyFactory__DelegateCallFailed.selector);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor2), data);
        vm.stopPrank();
    }

    function testFundsCanBeTransferredToAddressZeroWinner() public {
        bytes32 contestId = bytes32(abi.encode("contestId", "test"));
        uint256 closeTime = block.timestamp + 1 days;
        proxyFactory2.setContest(organizer, contestId, closeTime, address(distributor2));
        bytes32 salt = keccak256(abi.encode(organizer, contestId, address(distributor2)));

        assertEq(closeTime, proxyFactory2.saltToCloseTime(salt));
        console.log(proxyFactory2.saltToCloseTime(salt));
        console.log(closeTime);

        // getting the address of the proxy
        address proxyAddress = proxyFactory2.getProxyAddress(salt, address(distributor2));

        // set tokens, winners, percentages
        address token = address(jpycv2);
        address[] memory winners = new address[](2);
        winners[0] = user1;
        winners[1] = address(0);
        uint256[] memory percentages = new uint256[](2);
        percentages[0] = 5500;
        percentages[1] = 4000;

        // set data
        bytes memory data = abi.encodeWithSelector(Distributor.distribute.selector, token, winners, percentages, "");

        // sending tokens to proxy
        // vm.startPrank(sponsor);
        // MockERC20WithBlackList(token).transfer(proxyAddress, 10000 ether);
        // vm.stopPrank();

        // distribute
        vm.warp(closeTime + 1);
        vm.startPrank(organizer);
        vm.expectRevert(ProxyFactory.ProxyFactory__DelegateCallFailed.selector);
        proxyFactory2.deployProxyAndDistribute(contestId, address(distributor2), data);
        vm.stopPrank();
    }
}

// important links
// https://github.com/d-xo/weird-erc20/blob/main/src/ERC20.sol
