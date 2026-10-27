#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <random>

namespace utils {

const std::string gen_hash(size_t size) {
    static const char symbols[] =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const size_t capacity = sizeof(symbols) - 1;

    std::string hash(size, '\0');
    for (std::string::iterator i = hash.begin(); i != hash.end(); ++i) {
