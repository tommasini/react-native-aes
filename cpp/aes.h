// aes.h
#pragma once

#include <jsi/jsi.h>
#include <string>

using namespace facebook::jsi;
using namespace facebook::react;

void installAesModule(Runtime &runtime);
std::string performDecryption(const std::string &ciphertextHex, const std::string &keyHex, const std::string &ivHex, const std::string &algorithm);