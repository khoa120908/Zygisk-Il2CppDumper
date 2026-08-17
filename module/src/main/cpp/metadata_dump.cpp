#include "metadata_dump.h"

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "log.h"

namespace {

constexpr uint32_t kMetadataMagic = 0xFAB11BAF;
constexpr size_t kProbeSize = 0x1000;
constexpr size_t kScanChunk = 128 * 1024;
constexpr size_t kCopyChunk = 1024 * 1024;
constexpr size_t kMaxMappingToScan = 768ULL * 1024 * 1024;
constexpr size_t kMaxTotalDataScan = 512ULL * 1024 * 1024;
constexpr size_t kMaxMetadataSize = 1024ULL * 1024 * 1024;

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t file_offset = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool private_map = false;
    std::string perms;
    std::string path;

    size_t size() const { return end > start ? end - start : 0; }
};

struct MetadataCandidate {
    uintptr_t start = 0;
    uintptr_t end = 0;
    size_t size = 0;
    uint32_t version = 0;
    std::string map_path;
};

bool ensure_files_dir(const char *out_dir, std::string &files_dir) {
    if (!out_dir || !*out_dir) return false;
    files_dir = std::string(out_dir) + "/files";
    if (mkdir(files_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        LOGW("range dump: cannot create %s: %s", files_dir.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}

std::vector<MapEntry> read_maps() {
    std::vector<MapEntry> maps;
    std::ifstream in("/proc/self/maps");
    std::string line;
    while (std::getline(in, line)) {
        unsigned long start = 0, end = 0, file_offset = 0, inode = 0;
        char perms[5]{};
        char dev[32]{};
        int path_pos = 0;
        int matched = std::sscanf(line.c_str(), "%lx-%lx %4s %lx %31s %lu %n",
                                  &start, &end, perms, &file_offset, dev, &inode, &path_pos);
        if (matched < 6 || start >= end) continue;

        MapEntry entry;
        entry.start = static_cast<uintptr_t>(start);
        entry.end = static_cast<uintptr_t>(end);
        entry.file_offset = static_cast<uintptr_t>(file_offset);
        entry.perms = perms;
        entry.readable = perms[0] == 'r';
        entry.writable = perms[1] == 'w';
        entry.executable = perms[2] == 'x';
        entry.private_map = perms[3] == 'p';
        if (path_pos > 0 && static_cast<size_t>(path_pos) < line.size()) {
            entry.path = line.substr(static_cast<size_t>(path_pos));
            while (!entry.path.empty() && entry.path.front() == ' ') entry.path.erase(entry.path.begin());
        }
        maps.emplace_back(std::move(entry));
    }
    return maps;
}

bool is_libil2cpp(const MapEntry &map) {
    return map.path.find("libil2cpp.so") != std::string::npos;
}

bool is_named_metadata(const MapEntry &map) {
    return map.path.find("global-metadata.dat") != std::string::npos ||
           map.path.find("global-metadata") != std::string::npos;
}

bool is_scan_candidate(const MapEntry &map) {
    if (!map.readable || map.executable || map.size() < 0x80 || map.size() > kMaxMappingToScan)
        return false;
    if (is_named_metadata(map)) return true;
    if (map.path.empty()) return true;
    if (!map.path.empty() && map.path.front() == '[') return true;
    if (map.writable) return true;
    if (map.path.find("memfd:") != std::string::npos || map.path.find("/dev/ashmem") != std::string::npos)
        return true;
    return false;
}

bool pread_all(int fd, void *buffer, size_t size, uintptr_t address) {
    auto *out = static_cast<uint8_t *>(buffer);
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, out + done, size - done, static_cast<off_t>(address + done));
        if (n <= 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

bool looks_like_metadata_header(const uint8_t *probe, size_t probe_size, size_t available,
                                size_t &metadata_size, uint32_t &version) {
    if (!probe || probe_size < 0x80) return false;

    uint32_t sanity = 0;
    std::memcpy(&sanity, probe, sizeof(sanity));
    if (sanity != kMetadataMagic) return false;
    std::memcpy(&version, probe + sizeof(uint32_t), sizeof(version));
    if (version < 16 || version > 100) return false;

    // GlobalMetadataHeader is sanity/version followed by offset/count pairs.
    // The smallest valid positive offset is the header size on standard metadata.
    size_t min_offset = SIZE_MAX;
    const size_t word_count = probe_size / sizeof(uint32_t);
    const size_t header_search_words = std::min(word_count, static_cast<size_t>(0x200 / sizeof(uint32_t)));
    for (size_t i = 2; i + 1 < header_search_words; i += 2) {
        uint32_t offset = 0;
        uint32_t count = 0;
        std::memcpy(&offset, probe + i * 4, sizeof(offset));
        std::memcpy(&count, probe + (i + 1) * 4, sizeof(count));
        if (!offset && !count) continue;
        if (offset >= 0x80 && offset <= kProbeSize && (offset % 4) == 0)
            min_offset = std::min(min_offset, static_cast<size_t>(offset));
    }
    if (min_offset == SIZE_MAX || min_offset < 0x80 || min_offset > probe_size)
        return false;

    size_t max_end = min_offset;
    size_t pair_words = std::min(word_count, min_offset / sizeof(uint32_t));
    size_t valid_pairs = 0;
    for (size_t i = 2; i + 1 < pair_words; i += 2) {
        uint32_t offset32 = 0;
        uint32_t count32 = 0;
        std::memcpy(&offset32, probe + i * 4, sizeof(offset32));
        std::memcpy(&count32, probe + (i + 1) * 4, sizeof(count32));
        if (!offset32 && !count32) continue;
        uint64_t offset = offset32;
        uint64_t count = count32;
        if (offset < min_offset || offset > kMaxMetadataSize) return false;
        uint64_t end = offset + count;
        if (end < offset || end > kMaxMetadataSize) return false;
        max_end = std::max(max_end, static_cast<size_t>(end));
        ++valid_pairs;
    }

    if (valid_pairs < 8 || max_end <= min_offset || max_end > kMaxMetadataSize || max_end > available)
        return false;

    metadata_size = max_end;
    return true;
}

bool probe_candidate(int mem_fd, uintptr_t address, uintptr_t map_end,
                     size_t &metadata_size, uint32_t &version) {
    if (address >= map_end || map_end - address < 0x80) return false;
    size_t to_read = std::min(kProbeSize, static_cast<size_t>(map_end - address));
    std::vector<uint8_t> probe(to_read);
    if (!pread_all(mem_fd, probe.data(), probe.size(), address)) return false;
    return looks_like_metadata_header(probe.data(), probe.size(), map_end - address, metadata_size, version);
}

bool find_in_mapping(int mem_fd, const MapEntry &map, MetadataCandidate &candidate) {
    if (!is_scan_candidate(map)) return false;

    size_t metadata_size = 0;
    uint32_t version = 0;
    if (is_named_metadata(map) && probe_candidate(mem_fd, map.start, map.end, metadata_size, version)) {
        candidate.start = map.start;
        candidate.size = metadata_size;
        candidate.end = map.start + metadata_size;
        candidate.version = version;
        candidate.map_path = map.path;
        return true;
    }

    std::vector<uint8_t> chunk(kScanChunk + 3);
    size_t carry = 0;
    uintptr_t pos = map.start;
    const uint8_t first_magic_byte = 0xAF; // 0xFAB11BAF little-endian

    while (pos < map.end) {
        size_t want = std::min(kScanChunk, static_cast<size_t>(map.end - pos));
        ssize_t n = pread(mem_fd, chunk.data() + carry, want, static_cast<off_t>(pos));
        if (n <= 0) break;
        size_t total = carry + static_cast<size_t>(n);

        size_t i = 0;
        while (i + sizeof(uint32_t) <= total) {
            void *hit = std::memchr(chunk.data() + i, first_magic_byte, total - i - 3);
            if (!hit) break;
            size_t at = static_cast<uint8_t *>(hit) - chunk.data();
            uint32_t magic = 0;
            std::memcpy(&magic, chunk.data() + at, sizeof(magic));
            if (magic == kMetadataMagic) {
                uintptr_t address = pos - carry + at;
                if (address >= map.start && probe_candidate(mem_fd, address, map.end, metadata_size, version)) {
                    candidate.start = address;
                    candidate.size = metadata_size;
                    candidate.end = address + metadata_size;
                    candidate.version = version;
                    candidate.map_path = map.path;
                    return true;
                }
            }
            i = at + 1;
        }

        carry = std::min<size_t>(3, total);
        if (carry) std::memmove(chunk.data(), chunk.data() + total - carry, carry);
        pos += static_cast<size_t>(n);
    }
    return false;
}

bool copy_memory_range(int mem_fd, uintptr_t address, size_t size, const std::string &path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;

    std::vector<uint8_t> buffer(kCopyChunk);
    size_t copied = 0;
    while (copied < size) {
        size_t want = std::min(buffer.size(), size - copied);
        ssize_t n = pread(mem_fd, buffer.data(), want, static_cast<off_t>(address + copied));
        if (n <= 0) {
            LOGW("memory copy stopped at %zu/%zu: %s", copied, size, std::strerror(errno));
            out.close();
            return false;
        }
        out.write(reinterpret_cast<const char *>(buffer.data()), n);
        if (!out.good()) {
            out.close();
            return false;
        }
        copied += static_cast<size_t>(n);
    }
    out.flush();
    out.close();
    return copied == size;
}

bool write_range_report(const char *out_dir, const std::vector<MapEntry> &maps,
                        const MetadataCandidate *candidate) {
    std::string files_dir;
    if (!ensure_files_dir(out_dir, files_dir)) return false;

    uintptr_t il2cpp_start = UINTPTR_MAX;
    uintptr_t il2cpp_end = 0;
    uintptr_t named_meta_start = UINTPTR_MAX;
    uintptr_t named_meta_end = 0;
    size_t il2cpp_segments = 0;
    size_t metadata_segments = 0;

    for (const auto &map : maps) {
        if (is_libil2cpp(map)) {
            il2cpp_start = std::min(il2cpp_start, map.start);
            il2cpp_end = std::max(il2cpp_end, map.end);
            ++il2cpp_segments;
        }
        if (is_named_metadata(map)) {
            named_meta_start = std::min(named_meta_start, map.start);
            named_meta_end = std::max(named_meta_end, map.end);
            ++metadata_segments;
        }
    }

    const std::string final_path = files_dir + "/dump_info.txt";
    const std::string temp_path = final_path + ".tmp";
    std::ofstream out(temp_path, std::ios::out | std::ios::trunc);
    if (!out.is_open()) return false;

    out << "# Zygisk-Il2CppDumper runtime memory ranges\n";
    out << "PID=" << getpid() << "\n";
    if (il2cpp_segments) {
        out << "IL2CPP_START=0x" << std::hex << il2cpp_start << "\n";
        out << "IL2CPP_END=0x" << std::hex << il2cpp_end << "\n";
        out << "IL2CPP_SPAN=0x" << std::hex << (il2cpp_end - il2cpp_start) << "\n";
    } else {
        out << "IL2CPP_START=NOT_FOUND\nIL2CPP_END=NOT_FOUND\n";
    }

    if (metadata_segments) {
        out << "GLOBAL_METADATA_FILE_MAP_START=0x" << std::hex << named_meta_start << "\n";
        out << "GLOBAL_METADATA_FILE_MAP_END=0x" << std::hex << named_meta_end << "\n";
        out << "GLOBAL_METADATA_FILE_MAP_SPAN=0x" << std::hex << (named_meta_end - named_meta_start) << "\n";
    } else {
        out << "GLOBAL_METADATA_FILE_MAP_START=NOT_FOUND\nGLOBAL_METADATA_FILE_MAP_END=NOT_FOUND\n";
    }

    if (candidate && candidate->start && candidate->size) {
        out << "GLOBAL_METADATA_START=0x" << std::hex << candidate->start << "\n";
        out << "GLOBAL_METADATA_END=0x" << std::hex << candidate->end << "\n";
        out << "GLOBAL_METADATA_SIZE=0x" << std::hex << candidate->size << "\n";
        out << "GLOBAL_METADATA_VERSION=" << std::dec << candidate->version << "\n";
        out << "GLOBAL_METADATA_MAP=" << (candidate->map_path.empty() ? "<anonymous>" : candidate->map_path) << "\n";
    } else {
        out << "GLOBAL_METADATA_START=NOT_FOUND\nGLOBAL_METADATA_END=NOT_FOUND\n";
    }

    out << "\n# libil2cpp.so segments: start-end perms file_offset path\n";
    size_t index = 0;
    for (const auto &map : maps) {
        if (!is_libil2cpp(map)) continue;
        out << "IL2CPP_SEGMENT[" << std::dec << index++ << "]=0x" << std::hex << map.start
            << "-0x" << map.end << " " << map.perms << " file_off=0x" << map.file_offset
            << " " << map.path << "\n";
    }

    out << "\n# named global-metadata mappings\n";
    index = 0;
    for (const auto &map : maps) {
        if (!is_named_metadata(map)) continue;
        out << "METADATA_SEGMENT[" << std::dec << index++ << "]=0x" << std::hex << map.start
            << "-0x" << map.end << " " << map.perms << " file_off=0x" << map.file_offset
            << " " << map.path << "\n";
    }

    out.flush();
    out.close();
    if (std::rename(temp_path.c_str(), final_path.c_str()) != 0) {
        std::remove(temp_path.c_str());
        return false;
    }

    if (il2cpp_segments) {
        LOGI("libil2cpp range: 0x%" PRIxPTR "-0x%" PRIxPTR " span=0x%" PRIxPTR,
             il2cpp_start, il2cpp_end, il2cpp_end - il2cpp_start);
    } else {
        LOGW("libil2cpp range: not found in /proc/self/maps");
    }
    if (candidate && candidate->start) {
        LOGI("global-metadata range: 0x%" PRIxPTR "-0x%" PRIxPTR " size=0x%zx version=%u",
             candidate->start, candidate->end, candidate->size, candidate->version);
    }
    LOGI("range report: %s", final_path.c_str());
    return true;
}

} // namespace

bool save_runtime_ranges(const char *out_dir) {
    auto maps = read_maps();
    if (maps.empty()) {
        LOGW("range dump: /proc/self/maps is empty");
        return false;
    }
    return write_range_report(out_dir, maps, nullptr);
}

bool dump_global_metadata(const char *out_dir) {
    std::string files_dir;
    if (!ensure_files_dir(out_dir, files_dir)) return false;

    auto maps = read_maps();
    if (maps.empty()) {
        LOGW("metadata recovery: /proc/self/maps is empty");
        return false;
    }

    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0) {
        LOGW("metadata recovery: cannot open /proc/self/mem: %s", std::strerror(errno));
        write_range_report(out_dir, maps, nullptr);
        return false;
    }

    // Named metadata first; then small anonymous/writable data mappings.
    std::stable_sort(maps.begin(), maps.end(), [](const MapEntry &a, const MapEntry &b) {
        bool am = is_named_metadata(a);
        bool bm = is_named_metadata(b);
        if (am != bm) return am > bm;
        bool aa = is_scan_candidate(a);
        bool ba = is_scan_candidate(b);
        if (aa != ba) return aa > ba;
        if (aa && ba && a.size() != b.size()) return a.size() < b.size();
        return false;
    });

    MetadataCandidate candidate;
    size_t scanned = 0;
    for (const auto &map : maps) {
        if (!is_scan_candidate(map)) continue;
        if (!is_named_metadata(map)) {
            if (scanned + map.size() > kMaxTotalDataScan) continue;
            scanned += map.size();
        }
        if (find_in_mapping(mem_fd, map, candidate)) break;
    }

    if (!candidate.start || !candidate.size) {
        close(mem_fd);
        LOGW("metadata recovery: standard IL2CPP header not found (scanned up to %zu MiB)",
             scanned / (1024 * 1024));
        write_range_report(out_dir, maps, nullptr);
        return false;
    }

    LOGI("metadata candidate: addr=0x%" PRIxPTR " end=0x%" PRIxPTR " version=%u size=%zu map=%s",
         candidate.start, candidate.end, candidate.version, candidate.size,
         candidate.map_path.empty() ? "<anonymous>" : candidate.map_path.c_str());

    const std::string final_path = files_dir + "/global-metadata.dat";
    const std::string temp_path = final_path + ".tmp";
    bool ok = copy_memory_range(mem_fd, candidate.start, candidate.size, temp_path);
    close(mem_fd);

    write_range_report(out_dir, maps, &candidate);

    if (!ok) {
        std::remove(temp_path.c_str());
        return false;
    }
    if (std::rename(temp_path.c_str(), final_path.c_str()) != 0) {
        LOGW("metadata recovery: rename failed: %s", std::strerror(errno));
        std::remove(temp_path.c_str());
        return false;
    }

    LOGI("metadata recovered: version=%u size=%zu -> %s", candidate.version, candidate.size,
         final_path.c_str());
    return true;
}
