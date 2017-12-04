#include "gpsoauth/GPSOAuthClient.h"
#include "gpsoauth/GoogleKeyUtils.h"
#include <cpr/cpr.h>
#include <cryptopp/rsa.h>

namespace gpsoauth {

// perform_master_login

StringMap GPSOAuthClient::performMasterLogin(
    const std::string &email, const std::string password,
    const std::string &androidId, const std::string &service,
    const std::string &deviceCountry, const std::string &operatorCountry,
    const std::string &lang, int sdkVersion) {
  auto request = generateMasterLoginRequest(email, password, androidId, service,
                                            deviceCountry, operatorCountry,
                                            lang, sdkVersion);
  return performAuthRequest(request);
}

std::future<StringMap> GPSOAuthClient::performMasterLoginAsync(
    const std::string &email, const std::string password,
    const std::string &androidId, const std::string &service,
    const std::string &deviceCountry, const std::string &operatorCountry,
    const std::string &lang, int sdkVersion) {
  auto request = generateMasterLoginRequest(email, password, androidId, service,
                                            deviceCountry, operatorCountry,
                                            lang, sdkVersion);
  return performAuthRequestAsync(request);
}

StringMap GPSOAuthClient::performOAuth(
    const std::string &email, const std::string &masterToken,
    const std::string &androidId, const std::string &service,
    const std::string &app, const std::string &clientSig,
    const std::string &deviceCountry, const std::string &operatorCountry,
    const std::string &lang, int sdkVersion) {
  auto request =
    generateBaseRequest(email, masterToken, androidId, service, deviceCountry,
                        operatorCountry, lang, sdkVersion);
  request.emplace_back("app", app);
  request.emplace_back("client_sig", clientSig);
  return performAuthRequest(request);
}

// perform_oauth

std::future<StringMap> GPSOAuthClient::performOAuthAsync(
    const std::string &email, const std::string &masterToken,
    const std::string &androidId, const std::string &service,
    const std::string &app, const std::string &clientSig,
    const std::string &deviceCountry, const std::string &operatorCountry,
    const std::string &lang, int sdkVersion) {
  auto request =
      generateBaseRequest(email, masterToken, androidId, service, deviceCountry,
                          operatorCountry, lang, sdkVersion);
  request.emplace_back("app", app);
  request.emplace_back("client_sig", clientSig);
  return performAuthRequestAsync(request);
}

// _perform_auth_request

std::future<StringMap>
GPSOAuthClient::performAuthRequestAsync(GPSOAuthClient::Data data) {
  cpr::Payload payload{};
  for (const auto &d : data) {
    payload.AddPair({d.first, d.second});
  }

  return cpr::PostCallback(
      &parseResponse,
      cpr::Url{authUrl()}, cpr::Header{{"user-agent", userAgent()}}, payload,
      cpr::VerifySsl{false});
}

StringMap GPSOAuthClient::performAuthRequest(Data data)
{
  cpr::Payload payload{};
  for (const auto &d : data)
  {
    payload.AddPair({ d.first, d.second });
  }

  auto response = cpr::Post(
    cpr::Url{ authUrl() }, cpr::Header{ { "user-agent", userAgent() } }, payload,
    cpr::VerifySsl{ false });

  return parseResponse(response);
}

GPSOAuthClient::Data GPSOAuthClient::generateBaseRequest(
    const std::string &email, const std::string &encryptedPassword,
    const std::string &androidId, const std::string &service,
    const std::string &deviceCountry, const std::string &operatorCountry,
    const std::string &lang, int sdkVersion) {
  return {{"accountType", "HOSTED_OR_GOOGLE"},
          {"Email", email},
          {"has_permission", "1"},
          {"EncryptedPasswd", encryptedPassword},
          {"service", service},
          {"source", "android"},
          {"androidId", androidId},
          {"device_country", deviceCountry},
          {"operatorCountry", operatorCountry},
          {"lang", lang},
          {"sdk_version", std::to_string(sdkVersion)}};
}

GPSOAuthClient::Data GPSOAuthClient::generateMasterLoginRequest(
    const std::string &email, const std::string &password,
    const std::string &androidId, const std::string &service,
    const std::string &deviceCountry, const std::string &operatorCountry,
    const std::string &lang, int sdkVersion) {
  // The key is distirbuted with Google Play Services.
  // This one is from version 7.3.29.
  static const std::string b64Key =
      "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3"
      "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK"
      "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/"
      "6rmf5AAAAAwEAAQ==";
  static const auto androidKey = GoogleKeyUtils::keyFromB64(b64Key);
  auto signature = GoogleKeyUtils::createSignature(email, password, androidKey);
  auto request =
      generateBaseRequest(email, signature, androidId, service, deviceCountry,
                          operatorCountry, lang, sdkVersion);
  request.emplace_back("add_account", "1");
  return request;
}

StringMap GPSOAuthClient::parseResponse(const cpr::Response & response)
{
  if (response.status_code != 200)
  {
    return StringMap{ { "error", response.text } };
  }
  return GoogleKeyUtils::parseAuthResponse(response.text);
}

std::string GPSOAuthClient::version()
{
  return "0.0.5";
}

std::string GPSOAuthClient::authUrl()
{
  return "https://android.clients.google.com/auth";
}

std::string GPSOAuthClient::userAgent()
{
  return "GPSOAuthCpp/" + version();
}

} // namespace gpsoauth
