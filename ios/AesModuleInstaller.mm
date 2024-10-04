// AesModule.mm
#import "AesModule.h"
#import <React/RCTLog.h>
#import <React/RCTBridge.h>
#import <React/RCTBridge+Private.h>
#import <React/RCTCxxBridgeDelegate.h>
#import <ReactCommon/JSCallInvoker.h>
#import <ReactCommon/CallInvokerHolder.h>
#import <jsi/jsi.h>
#import <openssl/evp.h>
#import <openssl/rand.h>
#import <openssl/sha.h>
#import <openssl/hmac.h>
#import <vector>

using namespace facebook::jsi;
using namespace facebook::react;

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    static const char hex_digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        hex.push_back(hex_digits[byte >> 4]);
        hex.push_back(hex_digits[byte & 0x0F]);
    }
    return hex;
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned char byte = (unsigned char) std::stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string performDecryption(const std::string& ciphertextHex, const std::string& keyHex, const std::string& ivHex, const std::string& algorithm) {
    std::vector<unsigned char> ciphertext = hexToBytes(ciphertextHex);
    std::vector<unsigned char> key = hexToBytes(keyHex);
    std::vector<unsigned char> iv = hexToBytes(ivHex);

    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!cipher) {
        throw std::runtime_error("Invalid algorithm");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data());

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return std::string(plaintext.begin(), plaintext.end());
}

Value decrypt(Runtime& runtime, const Value* args, size_t count) {
    if (count != 4 || !args[0].isString() || !args[1].isString() || !args[2].isString() || !args[3].isString()) {
        throw JSError(runtime, "decrypt expects four string arguments");
    }

    std::string ciphertextHex = args[0].asString(runtime).utf8(runtime);
    std::string keyHex = args[1].asString(runtime).utf8(runtime);
    std::string ivHex = args[2].asString(runtime).utf8(runtime);
    std::string algorithm = args[3].asString(runtime).utf8(runtime);

    std::string plaintext = performDecryption(ciphertextHex, keyHex, ivHex, algorithm);

    return Value(runtime, String::createFromUtf8(runtime, plaintext));
}

void installAesModule(Runtime& runtime) {
    auto aesModule = Object(runtime);
    aesModule.setProperty(runtime, "decrypt", Function::createFromHostFunction(runtime, PropNameID::forAscii(runtime, "decrypt"), 4, decrypt));
    runtime.global().setProperty(runtime, "AesModule", std::move(aesModule));
}

extern "C" void install(facebook::jsi::Runtime& runtime) {
    installAesModule(runtime);
}

@implementation AesModule

RCT_EXPORT_MODULE()

- (void)installJSI {
    RCTBridge *bridge = [self.bridge valueForKey:@"parentBridge"];
    if (!bridge) {
        bridge = self.bridge;
    }
    if (bridge) {
        [bridge dispatchBlock:^{
            install(*bridge.runtime);
        } queue:RCTJSThread];
    }
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [self installJSI];
    }
    return self;
}

@end