#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.CADEXCOIN/cadexd.pid file instead
cadex_pid=$(<~/.CADEXCOIN/testnet3/cadexd.pid)
sudo gdb -batch -ex "source debug.gdb" cadexd ${cadex_pid}
