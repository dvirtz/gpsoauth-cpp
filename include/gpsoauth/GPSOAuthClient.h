#pragma once
#include "gpsoauth/StringMap.h"
#include <future>
#include <initializer_list>
#include <string>
#include <tuple>
#include <vector>

namespace cpr {
class Response;
}

namespace gpsoauth {

// URL: https://github.com/simon-weber/gpsoauth/blob/master/gpsoauth/__init__.py
class GPSOAuthClient {
public:
  // Perform an synchronous master login, which is what Android does when you
  // first add a Google account.
  //
  // Return a string map, eg::
  //
  // {
  //   'Auth': '...',
  //   'Email' : 'email@gmail.com',
  //   'GooglePlusUpgrade' : '1',
  //   'LSID' : '...',
  //   'PicasaUser' : 'My Name',
  //   'RopRevision' : '1',
  //   'RopText' : ' ',
  //   'SID' : '...',
  //   'Token' : 'oauth2rt_1/...',
  //   'firstName' : 'My',
  //   'lastName' : 'Name',
  //   'services' : 'hist,mail,googleme,...'
  // }
  static StringMap performMasterLogin(const std::string &email,
                                      const std::string password,
                                      const std::string &androidId,
                                      const std::string &service = "ac2dm",
                                      const std::string &deviceCountry = "us",
                                      const std::string &operatorCountry = "us",
                                      const std::string &lang = "en",
                                      int sdkVersion = 21);

  // Perform an asynchronous master login, which is what Android does when you
  // first add a Google account.
  //
  // Return a string map, eg::
  //
  // {
  //   'Auth': '...',
  //   'Email' : 'email@gmail.com',
  //   'GooglePlusUpgrade' : '1',
  //   'LSID' : '...',
  //   'PicasaUser' : 'My Name',
  //   'RopRevision' : '1',
  //   'RopText' : ' ',
  //   'SID' : '...',
  //   'Token' : 'oauth2rt_1/...',
  //   'firstName' : 'My',
  //   'lastName' : 'Name',
  //   'services' : 'hist,mail,googleme,...'
  // }
  static std::future<StringMap>
  performMasterLoginAsync(const std::string &email, const std::string password,
                          const std::string &androidId,
                          const std::string &service = "ac2dm",
                          const std::string &deviceCountry = "us",
                          const std::string &operatorCountry = "us",
                          const std::string &lang = "en", int sdkVersion = 21);

  // Use a master token from performMasterLoginAsync to perform OAuth to a
  // specific Google service.
  //
  // Return a string map, eg::
  //
  // {
  //   'Auth': '...',
  //   'LSID' : '...',
  //   'SID' : '..',
  //   'issueAdvice' : 'auto',
  //   'services' : 'hist,mail,googleme,...'
  // }
  //
  // To authenticate requests to this service, include a header
  //   ``Authorization: GoogleLogin auth=res["Auth"]``.
  static StringMap
  performOAuth(const std::string &email, const std::string &masterToken,
               const std::string &androidId, const std::string &service,
               const std::string &app, const std::string &clientSig,
               const std::string &deviceCountry = "us",
               const std::string &operatorCountry = "us",
               const std::string &lang = "en", int sdkVersion = 21);

  // Use a master token from performMasterLoginAsync to perform OAuth
  // asynchronously to a specific Google service.
  //
  // Return a string map, eg::
  //
  // {
  //   'Auth': '...',
  //   'LSID' : '...',
  //   'SID' : '..',
  //   'issueAdvice' : 'auto',
  //   'services' : 'hist,mail,googleme,...'
  // }
  //
  // To authenticate requests to this service, include a header
  //   ``Authorization: GoogleLogin auth=res["Auth"]``.
  static std::future<StringMap>
  performOAuthAsync(const std::string &email, const std::string &masterToken,
                    const std::string &androidId, const std::string &service,
                    const std::string &app, const std::string &clientSig,
                    const std::string &deviceCountry = "us",
                    const std::string &operatorCountry = "us",
                    const std::string &lang = "en", int sdkVersion = 21);

private:
  using Data = std::vector<std::pair<std::string, std::string>>;
  static StringMap performAuthRequest(Data data);
  static std::future<StringMap> performAuthRequestAsync(Data data);

  static Data generateBaseRequest(const std::string &email,
                                  const std::string &encryptedPassword,
                                  const std::string &androidId,
                                  const std::string &service,
                                  const std::string &deviceCountry,
                                  const std::string &operatorCountry,
                                  const std::string &lang, int sdkVersion);

  static Data generateMasterLoginRequest(
      const std::string &email, const std::string &password,
      const std::string &androidId, const std::string &service,
      const std::string &deviceCountry, const std::string &operatorCountry,
      const std::string &lang, int sdkVersion);

  static StringMap parseResponse(const cpr::Response &response);

  static std::string version();

  static std::string authUrl();
  
  static std::string userAgent();
};

} // namespace gpsoauth
