#include "gpsoauth/GoogleKeyUtils.h"
#include <array>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <regex>

namespace gpsoauth {

CryptoPP::RSAFunction GoogleKeyUtils::keyFromB64(const std::string &b64Key) {
  using namespace CryptoPP;

  std::string decoded;

  StringSource ss(b64Key, true,
                  new Base64Decoder(new StringSink(decoded)) // Base64Decoder
  );                                                         // StringSource

  // decoded uses big endian, hence the reverse()
  auto b = reinterpret_cast<const byte *>(decoded.data());
  auto modLength = Integer(b, 4u).ConvertToLong();
  Integer mod(b + 4, modLength);
  auto expLength = Integer(b + modLength + 4, 4u).ConvertToLong();
  Integer exponent(b + modLength + 8, expLength);
  CryptoPP::RSA::PublicKey pKey;
  pKey.Initialize(mod, exponent);
  return pKey;
}

std::vector<unsigned char>
GoogleKeyUtils::keyToStruct(const CryptoPP::RSAFunction &key) {
  std::vector<unsigned char> res;
  res.insert(res.end(), {0x00, 0x00, 0x00, 0x80}); // modLength
  for (auto i = key.GetModulus().ByteCount(); i > 0; --i) {
    res.push_back(key.GetModulus().GetByte(i - 1));
  }
  res.insert(res.end(), {0x00, 0x00, 0x00, 0x03}); // expLength
  for (auto i = key.GetPublicExponent().ByteCount(); i > 0; --i) {
    res.push_back(key.GetPublicExponent().GetByte(i - 1));
  }
  return res;
}

StringMap GoogleKeyUtils::parseAuthResponse(const std::string &text) {
  StringMap res;
  std::regex partsRe("(\n|^)([^=]+)=(.*)(\n|$)");
  std::transform(std::sregex_iterator(text.begin(), text.end(), partsRe),
                 std::sregex_iterator(), std::inserter(res, res.end()),
                 [&](const std::smatch &m) -> StringMap::value_type {
                   return {m[2], m[3]};
                 });

  return res;
}

std::string GoogleKeyUtils::createSignature(const std::string &email,
                                            const std::string &password,
                                            const CryptoPP::RSAFunction &key) {
  using namespace CryptoPP;

  auto toStruct = keyToStruct(key);

  std::array<byte, 133> encrypted;
  encrypted[0] = 0;

  ArraySource ss1(toStruct.data(), toStruct.size(), true,
                  new HashFilter(SHA1{}, new ArraySink(
                                             &encrypted[1], 4)));

  std::string plaintext = email + '\0' + password;
  
  RandomPool rng;

  RSAES_OAEP_SHA_Encryptor e(key);

  StringSource ss2(
      plaintext, true,
      new PK_EncryptorFilter(rng, e,
                             new ArraySink(&encrypted[5], 128)) // PK_EncryptorFilter
  );                                                    // StringSource

  std::string encoded;

  ArraySource ss3(
      encrypted.data(), encrypted.size(), true,
      new Base64URLEncoder(new StringSink(encoded)) // Base64URLEncoder
  );                                                // StringSource

  return encoded;
}

} // namespace gpsoauth
