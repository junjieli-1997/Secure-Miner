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
    for (std::string::iterator i = hash.begin(); i != hash.end(); ++i) {
      	// BEGIN SOLUTION
        int index = std::rand() % capacity;
        *i = symbols[index];
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

