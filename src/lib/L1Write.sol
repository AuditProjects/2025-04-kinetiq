// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract L1Write {
    event IocOrder(address indexed user, uint16 perp, bool isBuy, uint64 limitPx, uint64 sz);
    event VaultTransfer(address indexed user, address indexed vault, bool isDeposit, uint64 usd);
    event TokenDelegate(address indexed user, address indexed validator, uint64 _wei, bool isUndelegate);
    event CDeposit(address indexed user, uint64 _wei);
    event CWithdrawal(address indexed user, uint64 _wei);
    event SpotSend(address indexed user, address indexed destination, uint64 token, uint64 _wei);
    event UsdClassTransfer(address indexed user, uint64 ntl, bool toPerp);

    function sendIocOrder(uint16 perp, bool isBuy, uint64 limitPx, uint64 sz) external {
        emit IocOrder(msg.sender, perp, isBuy, limitPx, sz);
    }

    function sendVaultTransfer(address vault, bool isDeposit, uint64 usd) external {
        emit VaultTransfer(msg.sender, vault, isDeposit, usd);
    }
    // 质押/解质押 （isUndelegate）
    // 将当前合约的 staking balance 中的资金，正式分配给某个 validator
    function sendTokenDelegate(address validator, uint64 _wei, bool isUndelegate) external {
        emit TokenDelegate(msg.sender, validator, _wei, isUndelegate);
    }

    // 质押准备
    // 将当前合约在 Core 的 Spot Balance（可用余额） 转入
    function sendCDeposit(uint64 _wei) external {
        emit CDeposit(msg.sender, _wei);
    }

    function sendCWithdrawal(uint64 _wei) external {
        emit CWithdrawal(msg.sender, _wei);
    }

    function sendSpot(address destination, uint64 token, uint64 _wei) external {
        emit SpotSend(msg.sender, destination, token, _wei);
    }

    function sendUsdClassTransfer(uint64 ntl, bool toPerp) external {
        emit UsdClassTransfer(msg.sender, ntl, toPerp);
    }
}
