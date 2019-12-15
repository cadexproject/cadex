Cadex staging tree 2.1.1
=============================

https://www.cadexcoin.tech/


What is Cadex?
----------------

Cadex is an experimental digital currency that enables anonymous, instant
payments to anyone, anywhere in the world. Cadex uses peer-to-peer technology
to operate with no central authority: managing transactions and issuing money
are carried out collectively by the network. Cadex is the name of the open
source software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Cadex software, see https://www.cadexcoin.tech/


How do I build the software?
----------------------------

The examples below presume you have a basic build environment installed:


### Static compile

    git clone https://github.com/cadexproject/cadex
    cd cadex/depends
    make HOST=x86_64-linux-gnu
    cd ..
    ./autogen.sh
    ./configure --prefix=`pwd`/depends/x86_64-linux-gnu
    make

### Shared binary

    wget https://github.com/codablock/bls-signatures/archive/v20181101.zip
    unzip v20181101.zip
    cd bls-signatures-20181101
    mkdir build
    cd build
    cmake ..
    make install

    (if you receive an error here, you need to run as the root user; as the system is trying to install a library)

    cd ../..
    git clone https://github.com/cadexproject/cadex
    cd cadex
    ./autogen.sh
    ./configure
    make

    * note: if you do not have libdb4.8 installed, no issues will be created by using 5.1 or 5.3; but the wallets
             will not be portable! to achieve this; simply append --with-incompatible-bdb to the configure statement.


License
-------

Cadex is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is meant to be stable. Development is normally done in separate branches.
[Tags](https://github.com/cadexproject/cadex/tags) are created to indicate new official,
stable release versions of Cadex.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

Credits
-------

Cadex uses the Dash Core platform; building upon it to provide extra functionality.

