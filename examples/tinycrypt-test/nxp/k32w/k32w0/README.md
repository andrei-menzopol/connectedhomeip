# CHIP K32W061 Tinycrypt Example Application

## Building

In order to build the Project CHIP example, we recommend using a Linux
distribution (the demo-application was compiled on Ubuntu 20.04).

-   Download [K32W061 SDK 2.6.4 for Project CHIP](https://mcuxpresso.nxp.com/).
    Creating an nxp.com account is required before being able to download the
    SDK. Once the account is created, login and follow the steps for downloading
    SDK_2_6_4_K32W061DK6. The SDK Builder UI selection should be similar with
    the one from the image below.
    ![MCUXpresso SDK Download](../../platform/nxp/k32w/k32w0/doc/images/mcux-sdk-download.JPG)

-   Start building the application

```
user@ubuntu:~/Desktop/git/connectedhomeip$ export K32W061_SDK_ROOT=/home/user/Desktop/SDK_2_6_4_K32W061DK6/
user@ubuntu:~/Desktop/git/connectedhomeip$ ./third_party/k32w_sdk/sdk_fixes/patch_k32w_sdk.sh
user@ubuntu:~/Desktop/git/connectedhomeip$ source ./scripts/activate.sh
user@ubuntu:~/Desktop/git/connectedhomeip$ ./third_party/nxp/tinycrypt/patch_tinycrypt.sh
user@ubuntu:~/Desktop/git/connectedhomeip$ cd examples/tinycrypt-test/nxp/k32w/k32w0
user@ubuntu:~/Desktop/git/connectedhomeip/examples/tinycrypt-test/nxp/k32w/k32w0$ gn gen out/debug --args="k32w0_sdk_root=\"${K32W061_SDK_ROOT}\" is_debug=false chip_crypto=\"mbedtls\" chip_with_se05x=0"
user@ubuntu:~/Desktop/git/connectedhomeip/examples/tinycrypt-test/nxp/k32w/k32w0$ ninja -C out/debug
user@ubuntu:~/Desktop/git/connectedhomeip/examples/tinycrypt-test/nxp/k32w/k32w0$ $K32W061_SDK_ROOT/tools/imagetool/sign_images.sh out/debug/
```

Note that "patch_k32w_sdk.sh" script must be run for patching the K32W061 SDK
2.6.4.

Note that "patch_tinycrypt.sh" script must be run for patching the matter, openthread & mbedtls repos.

In case signing errors are encountered when running the "sign_images.sh" script
install the recommanded packages (python version > 3, pip3, pycrypto,
pycryptodome):

```
user@ubuntu:~$ python3 --version
Python 3.8.2
user@ubuntu:~$ pip3 --version
pip 20.0.2 from /usr/lib/python3/dist-packages/pip (python 3.8)
user@ubuntu:~$ pip3 list | grep -i pycrypto
pycrypto               2.6.1
pycryptodome           3.9.8
```

The resulting output file can be found in out/debug/chip-k32w061-tinycrypt-test.

<a name="flashdebug"></a>

## Flashing and debugging

Program the firmware using the official
[OpenThread Flash Instructions](https://github.com/openthread/ot-nxp/tree/main/src/k32w0/k32w061#flash-binaries).

All you have to do is to replace the Openthread binaries from the above
documentation with _out/debug/chip-k32w061-tinycrypt-test.bin_ if DK6Programmer.

If MCUXpresso is used import a new example from the SDK (such as k32w061dk6_ed_bm) and make sure the settings are as in the link above. Then, in Debug configuration -> Main -> C/C++ Application set the path to the compiled and signed elf-file chip-k32w061-tinycrypt-test.

Now you can load the binary on the board.
Open a serial port and you should see debug messages with timings for the ecc crypto operations.

![Debug configuration](../../../../platform/nxp/k32w/k32w0/doc/images/debug-configuration.JPG)