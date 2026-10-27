#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>

namespace utils {

const std::string gen_hash(size_t size) {
    static const char symbols[] =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const size_t capacity = sizeof(symbols) - 1;

    std::string hash(size, '\0');

    /* SECURE: Use std::random_device for non-deterministic seed */
    std::random_device rd;
    /* Use Mersenne Twister engine */
    std::mt19937 gen(rd());
    /* Uniform distribution guarantees no modulo bias */
    std::uniform_int_distribution<size_t> dis(0, capacity - 1);

    for (std::string::iterator i = hash.begin(); i != hash.end(); ++i) {
        *i = symbols[dis(gen)];
    }
    return hash;
}

}  // namespace utils

// BEGIN ENTRYPOINT
int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <length>\n";
        return 2;
    }

    size_t length = std::stoul(argv[1]);
    std::string hash = utils::gen_hash(length);
    std::cout << hash << std::endl;

    return 0;
}

