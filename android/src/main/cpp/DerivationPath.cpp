#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

struct DerivationPathIndex {
    uint32_t value = 0;
    bool hardened = true;

    DerivationPathIndex() = default;
    DerivationPathIndex(uint32_t value, bool hardened = true)
            : value(value), hardened(hardened) {}

    /// The derivation index.
    uint32_t derivationIndex() const {
        if (hardened) {
            return value | 0x80000000;
        } else {
            return value;
        }
    }

    std::string string() const {
        if (hardened) {
            return std::to_string(value) + "'";
        } else {
            return std::to_string(value);
        }
    }
};

struct DerivationPath {
    std::vector<DerivationPathIndex> indices;

    DerivationPath() = default;
    explicit DerivationPath(std::vector<DerivationPathIndex> indices)
            : indices(std::move(indices)) {}

    explicit DerivationPath(const std::string& string);
};

DerivationPath::DerivationPath(const std::string &string) {
    const auto* it = string.data();
    const auto* end = string.data() + string.size();

    if (it != end && *it == 'm') {
        ++it;
    }
    if (it != end && *it == '/') {
        ++it;
    }

    while (it != end) {
        uint32_t value;
        if (std::sscanf(it, "%ud", &value) != 1) {
            throw std::invalid_argument("Invalid component");
        }
        while (it != end && isdigit(*it)) {
            ++it;
        }

        auto hardened = (it != end && *it == '\'');
        if (hardened) {
            ++it;
        }
        indices.emplace_back(value, hardened);

        if (it == end) {
            break;
        }
        if (*it != '/') {
            throw std::invalid_argument("Components should be separated by '/'");
        }
        ++it;
    }
}

inline bool operator==(const DerivationPathIndex& lhs, const DerivationPathIndex& rhs) {
    return lhs.value == rhs.value && lhs.hardened == rhs.hardened;
}

inline bool operator==(const DerivationPath& lhs, const DerivationPath& rhs) {
    return std::equal(lhs.indices.begin(), lhs.indices.end(), rhs.indices.begin(),
                      rhs.indices.end());
}
