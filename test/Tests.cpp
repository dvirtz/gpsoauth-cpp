#include "gpsoauth/GPSOAuthClient.h"
#include "gpsoauth/GoogleKeyUtils.h"
#include "config.h"
#include <catch/catch.hpp>
#include <cryptopp/rsa.h>
#include <yaml-cpp/yaml.h>

auto config = YAML::LoadFile(config_yaml);
static auto conf(const std::string &prop) {
  return config[prop].as<std::string>();
};

using namespace gpsoauth;

TEST_CASE("static signature") {
  auto username = "someone@google.com";
  auto password = "apassword";
  auto b64Key = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3"
                "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK"
                "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/"
                "6rmf5AAAAAwEAAQ==";
  auto key = GoogleKeyUtils::keyFromB64(b64Key);
  REQUIRE(
      GoogleKeyUtils::createSignature(username, password, key).substr(0, 6) ==
      "AFcb4K");
}

TEST_CASE("login") {
  SECTION("login with invalid credential fails") {
    auto response = GPSOAuthClient::performMasterLogin("", "", "");
    REQUIRE(response.count("error") == 1);
    REQUIRE(response.count("Token") == 0);
  }
  SECTION("login with valid credentials succeeds") {
    auto response = GPSOAuthClient::performMasterLogin(
        conf("email"), conf("password"), conf("androidId"));
    REQUIRE(response.count("Token") == 1);
  }
}

TEST_CASE("OAuth") {
  SECTION("OAuth with valid credentials succeeds") {
    auto response = GPSOAuthClient::performMasterLogin(
        conf("email"), conf("password"), conf("androidId"));
    auto token = response.at("Token");

    response = GPSOAuthClient::performOAuth(conf("email"), token, conf("androidId"),
                                                conf("service"), conf("app"), conf("clientSig"));
    REQUIRE(response.count("Auth") == 1);
    REQUIRE(response.count("Expiry") == 1);
  }

  SECTION("OAuth should fail with invalid token") {
    auto response = GPSOAuthClient::performOAuth(conf("email"), "", conf("androidId"),
                                                conf("service"), conf("app"), conf("clientSig"));
    REQUIRE(response.count("error") == 1);
  }
}
