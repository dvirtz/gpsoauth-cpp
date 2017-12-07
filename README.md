# gpsoauth-cpp
A C++ client library for Google Play Services OAuth.

Based on Simon Weber's [Python](https://github.com/simon-weber/gpsoauth) library.

## Build status
[![Build Status](https://travis-ci.org/dvirtz/gpsoauth-cpp.svg?branch=master)](https://travis-ci.org/dvirtz/gpsoauth-cpp) [![Build status](https://ci.appveyor.com/api/projects/status/0753uvpy8pun19rr?svg=true)](https://ci.appveyor.com/project/dvirtz/gpsoauth-cpp)

## Example
```C++
#include "gpsoauth/GPSOAuthClient.h"
...
auto response = gpsoauth::GPSOAuthClient::performMasterLogin(email, password, androidId);
auto token = response.at("Token");

response = gpsoauth::GPSOAuthClient::performOAuth(email, token, androidId,
                                        service, app, clientSig);
assert(response.count("Auth") == 1);
assert(response.count("Expiry") == 1);
```

## Build
```sh
cmake -B<build_folder> -G<generator> ...
cmake --build <build_folder>
```

If you don't want to build tests pass `-DBUILD_TESTS=OFF` to CMake.
Otherwise, you should add a valid email and password to test/config.yaml file to run the tests.
Then, run the tests with
```sh
cd <build_folder>
ctest
```

## Dependencies
gpsoauth-cpp uses [Hunter](https://github.com/ruslo/hunter) package manager which automatically downloads and builds its dependencies.
The library depends on:
* [cpr](https://github.com/whoshuu/cpr) - for networking
* [Crypto++](https://github.com/weidai11/cryptopp) - for encription

The tests depend on:
* [Catch2](https://github.com/catchorg/Catch2) - test framework
* [yaml-cpp](https://github.com/jbeder/yaml-cpp) - test configuration
