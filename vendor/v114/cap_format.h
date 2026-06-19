// cap_format.h - Binary container format for v1.14 parity-sweep captures.
//
// Layout:
//   Header: magic(8) version(4) hash_seq(8) stage_count(4) flags(4) reserved(4)
//   Record: stage_id(4) in_len(4) out_len(4) reserved(4) in_bytes out_bytes
//
// Endianness: little-endian host order. Header-only for use by replay tools.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

namespace deroluna::replay {

enum class StageId : uint32_t {
    Salsa20Init    = 1,
    Rc4Ksa         = 2,
    BranchDispatch = 3,
    V114Encode     = 4,
    V114SaBuild    = 5,
    Sha256OfSa     = 6,
};

inline const char* stage_name(StageId stage) {
    switch (stage) {
    case StageId::Salsa20Init:    return "salsa20_init";
    case StageId::Rc4Ksa:         return "rc4_ksa";
    case StageId::BranchDispatch: return "branch_dispatch";
    case StageId::V114Encode:     return "v114_encode";
    case StageId::V114SaBuild:    return "v114_sa_build";
    case StageId::Sha256OfSa:     return "sha256_of_sa";
    }
    return "unknown";
}

#pragma pack(push, 1)
struct CapHeader {
    char magic[8];
    uint32_t version;
    uint64_t hash_seq;
    uint32_t stage_count;
    uint32_t flags;
    uint32_t reserved;
};

struct StageHeader {
    uint32_t stage_id;
    uint32_t in_len;
    uint32_t out_len;
    uint32_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(CapHeader) == 32, "CapHeader layout");
static_assert(sizeof(StageHeader) == 16, "StageHeader layout");

inline constexpr uint32_t kCapVersion = 1;
inline constexpr char kCapMagic[8] = {'D', 'L', 'C', 'A', 'P', 0, 0, 0};

struct StageRecord {
    StageId stage_id;
    uint32_t in_len;
    uint32_t out_len;
    const uint8_t* in_bytes;
    const uint8_t* out_bytes;
};

class CaptureWriter {
public:
    bool open(const char* path, uint64_t hash_seq) {
        close();
        f_ = std::fopen(path, "wb");
        if (!f_) return false;

        CapHeader header{};
        std::memcpy(header.magic, kCapMagic, sizeof(header.magic));
        header.version = kCapVersion;
        header.hash_seq = hash_seq;
        header.stage_count = 0;
        header.flags = 0;
        header.reserved = 0;
        stage_count_ = 0;

        if (std::fwrite(&header, 1, sizeof(header), f_) != sizeof(header)) {
            std::fclose(f_);
            f_ = nullptr;
            return false;
        }
        return true;
    }

    bool write_stage(StageId id,
                     const uint8_t* in_bytes, size_t in_len,
                     const uint8_t* out_bytes, size_t out_len) {
        if (!f_) return false;
        if (in_len > std::numeric_limits<uint32_t>::max() ||
            out_len > std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        if ((in_len != 0 && in_bytes == nullptr) ||
            (out_len != 0 && out_bytes == nullptr)) {
            return false;
        }

        StageHeader stage{};
        stage.stage_id = static_cast<uint32_t>(id);
        stage.in_len = static_cast<uint32_t>(in_len);
        stage.out_len = static_cast<uint32_t>(out_len);
        stage.reserved = 0;

        if (std::fwrite(&stage, 1, sizeof(stage), f_) != sizeof(stage)) return false;
        if (in_len != 0 &&
            std::fwrite(in_bytes, 1, in_len, f_) != in_len) {
            return false;
        }
        if (out_len != 0 &&
            std::fwrite(out_bytes, 1, out_len, f_) != out_len) {
            return false;
        }
        ++stage_count_;
        return true;
    }

    bool close() {
        if (!f_) return true;
        bool ok = true;
        if (std::fseek(f_, offsetof(CapHeader, stage_count), SEEK_SET) != 0) {
            ok = false;
        } else if (std::fwrite(&stage_count_, 1, sizeof(stage_count_), f_) !=
                   sizeof(stage_count_)) {
            ok = false;
        }
        if (std::fclose(f_) != 0) ok = false;
        f_ = nullptr;
        return ok;
    }

    ~CaptureWriter() {
        if (f_) std::fclose(f_);
    }

private:
    std::FILE* f_ = nullptr;
    uint32_t stage_count_ = 0;
};

class CaptureReader {
public:
    bool open(const char* path) {
        buf_.clear();
        offsets_.clear();
        header_ = {};

        std::FILE* file = std::fopen(path, "rb");
        if (!file) return false;
        if (std::fseek(file, 0, SEEK_END) != 0) {
            std::fclose(file);
            return false;
        }
        long sz = std::ftell(file);
        if (sz < 0) {
            std::fclose(file);
            return false;
        }
        if (std::fseek(file, 0, SEEK_SET) != 0) {
            std::fclose(file);
            return false;
        }
        if (sz < static_cast<long>(sizeof(CapHeader))) {
            std::fclose(file);
            return false;
        }

        buf_.resize(static_cast<size_t>(sz));
        size_t got = std::fread(buf_.data(), 1, buf_.size(), file);
        std::fclose(file);
        if (got != buf_.size()) return false;

        if (std::memcmp(buf_.data(), kCapMagic, sizeof(kCapMagic)) != 0) {
            return false;
        }
        const auto* header = reinterpret_cast<const CapHeader*>(buf_.data());
        if (header->version != kCapVersion) return false;
        header_ = *header;

        size_t cur = sizeof(CapHeader);
        for (uint32_t i = 0; i < header_.stage_count; ++i) {
            if (cur + sizeof(StageHeader) > buf_.size()) break;
            offsets_.push_back(cur);

            const auto* stage =
                reinterpret_cast<const StageHeader*>(buf_.data() + cur);
            size_t payload = static_cast<size_t>(stage->in_len) +
                             static_cast<size_t>(stage->out_len);
            if (payload > buf_.size() ||
                cur + sizeof(StageHeader) > buf_.size() - payload) {
                break;
            }
            cur += sizeof(StageHeader) + payload;
        }
        return true;
    }

    uint64_t hash_seq() const { return header_.hash_seq; }
    uint32_t stage_count() const { return header_.stage_count; }

    bool read_stage(uint32_t idx, StageRecord* out) const {
        if (!out) return false;
        if (idx >= offsets_.size()) return false;

        size_t cur = offsets_[idx];
        if (cur + sizeof(StageHeader) > buf_.size()) return false;

        const auto* stage =
            reinterpret_cast<const StageHeader*>(buf_.data() + cur);
        size_t payload = static_cast<size_t>(stage->in_len) +
                         static_cast<size_t>(stage->out_len);
        if (payload > buf_.size() ||
            cur + sizeof(StageHeader) > buf_.size() - payload) {
            return false;
        }

        out->stage_id = static_cast<StageId>(stage->stage_id);
        out->in_len = stage->in_len;
        out->out_len = stage->out_len;
        out->in_bytes = buf_.data() + cur + sizeof(StageHeader);
        out->out_bytes = out->in_bytes + stage->in_len;
        return true;
    }

private:
    std::vector<uint8_t> buf_;
    CapHeader header_{};
    std::vector<size_t> offsets_;
};

}  // namespace deroluna::replay
