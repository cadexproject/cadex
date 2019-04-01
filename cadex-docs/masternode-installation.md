MASTERNODE CONFIGURATIONS
-------------------------
1) Using the control wallet, enter the debug console (Tools > Debug console) and type the following command:
```
masternode genkey (This will be the masternode’s privkey. We’ll use this later…)
```
2) Using the control wallet still, enter the following command:
```
getaccountaddress chooseAnyNameForYourMasternode
```
3) Still in the control wallet, send 100,000 CADEX to the address you generated in step 2 (Be 100% sure that you entered the address correctly. You can verify this when you paste the address into the “Pay To:” field, the label will autopopulate with the name you chose”, also make sure this is exactly 100,000 CADEX; No less, no more.)
4) Still in the control wallet, enter the command into the console (This gets the proof of transaction of sending 100,000):
```
masternode outputs
```
5) Still on the main computer, go into the cadex data directory, by default in Windows it’ll be
```
%Appdata%/CADEXCOIN
```
or Linux
```
cd ~/.CADEXCOIN
```
Find masternode.conf and add the following line to it:
```
# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index
```
or follow here
```
<Name of Masternode(Use the name you entered earlier for simplicity)> <Unique IP address>:51472 <The result of Step 1> <Result of Step 4> <The number after the long line in Step 4>
```
B. VPS Remote wallet install
----------------------------
1. From your home directory, download the latest version from the CADEX GitHub repository:
```
wget https://github.com/cadexproject/cadex/releases/download/v1.0.0/ubuntu16-cli.tar.gz
```
2. Unzip and extract:  
```
tar -xvf ubuntu16-cli.tar.gz
```
3. Go to your cadexcoin directory:
```
cd ubuntu16
```
4. Note: If this is the first time running the wallet in the VPS, you’ll need to attempt to start the wallet 
```
./cadexd
```
5. stop cadexd with
```
CTRL+C
```
6. Now on the masternodes, find the CADEX data directory here.(Linux: ~/.CADEXCOIN)
```
cd ~/.CADEXCOIN
```
7. Open the cadex.conf by typing
```
vi cadex.conf or nano cadex.conf 
```
8. Add the below code in the cadex.conf file 
```
 rpcuser=long random username
 rpcpassword=longer random password
 rpcallowip=127.0.0.1
 rpcport=28280
 listen=1
 server=1
 daemon=1
 logtimestamps=1
 maxconnections=80
 masternode=1
 externalip=your vps ip address
 masternodeprivkey=Result of Step 1
```
9. start your vps cadex daemon
```
./cadexd
```
10. Start your masternode from your desktop wallet
```
masternode start-alias MN1
```
