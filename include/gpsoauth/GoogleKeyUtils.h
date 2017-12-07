#pragma once
#include "gpsoauth/StringMap.h"
#include <vector>

namespace CryptoPP {
class RSAFunction;
}

namespace gpsoauth {
class GoogleKeyUtils {
public:
  // key_from_b64
  static CryptoPP::RSAFunction keyFromB64(const std::string &b64Key);

  // key_to_struct
  static std::vector<unsigned char>
  keyToStruct(const CryptoPP::RSAFunction &key);

  // parse_auth_response
  static StringMap parseAuthResponse(const std::string &text);

  // signature
  static std::string createSignature(const std::string &email,
                                     const std::string &password,
                                     const CryptoPP::RSAFunction &key);
};
} // namespace gpsoauth
