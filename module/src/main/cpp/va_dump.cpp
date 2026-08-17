#include "va_dump.h"

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
#include <utility>
#include <vector>

#include "log.h"

namespace {

constexpr size_t kIoChunk = 1024 * 1024;
constexpr uint64_t kMaxVaSpan = 1024ULL * 1024 * 1024;

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uint64_t file_offset = 0;
    bool readable = false;
    bool writable = false;
    std::string perms;
    std::string path;

    uint64_t size() const {
        return end > start ? static_cast<uint64_t>(end - start) : 0;
    }
};

std::string trim_left(std::string value) {
    auto pos = value.find_first_not_of(" \t");
    if (pos == std::string::npos) return {};
    return value.substr(pos);
}

std::vector<MapEntry> read_maps() {
    std::vector<MapEntry> maps;
    std::ifstream in("/proc/self/maps");
    std::string line;
    while (std::getline(in, line)) {
        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[5] = {};
        char dev[32] = {};
        int consumed = 0;
        int matched = std::sscanf(line.c_str(), "%lx-%lx %4s %lx %31s %lu %n",
                                  &start, &end, perms, &offset, dev, &inode, &consumed);
        if (matched < 6 || end <= start) continue;

        MapEntry entry;
        entry.start = static_cast<uintptr_t>(start);
        entry.end = static_cast<uintptr_t>(end);
        entry.file_offset = static_cast<uint64_t>(offset);
        entry.perms = perms;
        entry.readable = entry.perms.size() > 0 && entry.perms[0] == 'r';
        entry.writable = entry.perms.size() > 1 && entry.perms[1] == 'w';
        if (consumed > 0 && static_cast<size_t>(consumed) < line.size()) {
            entry.path = trim_left(line.substr(static_cast<size_t>(consumed)));
        }
        maps.emplace_back(std::move(entry));
    }
    return maps;
}

bool ensure_output_dir(const char *out_dir) {
    if (!out_dir || !*out_dir) return false;
    if (mkdir(out_dir, 0700) == 0 || errno == EEXIST) return true;
    LOGE("va dump: mkdir %s failed: %s", out_dir, strerror(errno));
    return false;
}

bool copy_mapping(int mem_fd, int out_fd, const MapEntry &entry,
                  uintptr_t base, uint64_t output_size, uint64_t *written) {
    if (written) *written = 0;
    if (!entry.readable || entry.start < base || entry.size() == 0) return false;

    uint64_t out_offset = static_cast<uint64_t>(entry.start - base);
    if (out_offset >= output_size) return false;
    uint64_t total = std::min<uint64_t>(entry.size(), output_size - out_offset);

    std::vector<unsigned char> buffer(kIoChunk);
    uint64_t done = 0;
    while (done < total) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), total - done));
        ssize_t got = pread(mem_fd, buffer.data(), want,
                            static_cast<off_t>(entry.start + done));
        if (got <= 0) {
            LOGW("va dump: pread 0x%" PRIxPTR " failed at +0x%" PRIx64 ": %s",
                 entry.start, done, strerror(errno));
            break;
        }
        ssize_t put = pwrite(out_fd, buffer.data(), static_cast<size_t>(got),
                             static_cast<off_t>(out_offset + done));
        if (put != got) {
            LOGW("va dump: pwrite +0x%" PRIx64 " failed: %s",
                 out_offset + done, strerror(errno));
            break;
        }
        done += static_cast<uint64_t>(got);
    }
    if (written) *written = done;
    return done == total;
}

} // namespace

bool dump_va_libil2cpp(const char *out_dir) {
    if (!ensure_output_dir(out_dir)) return false;

    auto maps = read_maps();
    std::vector<MapEntry> all;
    for (const auto &m : maps) {
        if (m.readable && m.path.find("libil2cpp.so") != std::string::npos) {
            all.push_back(m);
        }
    }
    if (all.empty()) {
        LOGW("va dump: no readable libil2cpp.so mappings found");
        return false;
    }

    // Use the largest offset-0 mapping as the actual image base. This avoids a
    // smaller duplicate mapping created by NativeBridge/Houdini being selected.
    const MapEntry *primary_ptr = nullptr;
    for (const auto &m : all) {
        if (m.file_offset != 0) continue;
        if (!primary_ptr || m.size() > primary_ptr->size()) primary_ptr = &m;
    }
    if (!primary_ptr) {
        LOGE("va dump: no file_off=0 libil2cpp mapping found");
        return false;
    }
    MapEntry primary = *primary_ptr;
    const uintptr_t base = primary.start;
    const std::string source_path = primary.path;

    // Only keep the mappings belonging to this concrete backing path and the
    // same VA image cluster. The latter prevents a second translated mapping
    // far away in the address space from inflating the dump by gigabytes.
    std::vector<MapEntry> segments;
    uintptr_t image_end = base;
    for (const auto &m : all) {
        if (m.path != source_path) continue;
        if (m.start < base) continue;
        uint64_t rel = static_cast<uint64_t>(m.start - base);
        if (rel >= kMaxVaSpan) continue;
        segments.push_back(m);
        if (m.end > image_end) image_end = m.end;
    }
    if (segments.empty() || image_end <= base) {
        LOGE("va dump: no mappings in selected image cluster");
        return false;
    }

    const uint64_t output_size = static_cast<uint64_t>(image_end - base);
    if (output_size == 0 || output_size > kMaxVaSpan) {
        LOGE("va dump: unreasonable image span 0x%" PRIx64, output_size);
        return false;
    }

    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0) {
        LOGE("va dump: open /proc/self/mem failed: %s", strerror(errno));
        return false;
    }

    std::string tmp = std::string(out_dir) + "/libil2cpp.vadump.so.tmp";
    std::string final_path = std::string(out_dir) + "/libil2cpp.vadump.so";
    std::string report_path = std::string(out_dir) + "/vadump_info.txt";
    std::string base_path = std::string(out_dir) + "/vadump_base.txt";

    int out_fd = open(tmp.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (out_fd < 0) {
        LOGE("va dump: create %s failed: %s", tmp.c_str(), strerror(errno));
        close(mem_fd);
        return false;
    }
    if (ftruncate(out_fd, static_cast<off_t>(output_size)) != 0) {
        LOGE("va dump: ftruncate 0x%" PRIx64 " failed: %s", output_size, strerror(errno));
        close(out_fd);
        close(mem_fd);
        unlink(tmp.c_str());
        return false;
    }

    // Non-writable mappings first, writable mappings last. If a protector has
    // overlapping aliases, the live writable copy wins in the final image.
    std::stable_sort(segments.begin(), segments.end(), [](const MapEntry &a, const MapEntry &b) {
        if (a.writable != b.writable) return !a.writable && b.writable;
        return a.start < b.start;
    });

    std::ofstream report(report_path, std::ios::trunc);
    report << "# libil2cpp VA-layout memory dump\n";
    report << "BASE=0x" << std::hex << base << "\n";
    report << "END=0x" << std::hex << image_end << "\n";
    report << "SPAN=0x" << std::hex << output_size << "\n";
    report << "SOURCE_PATH=" << source_path << "\n";
    report << "FORMULA=output_offset=mapping.start-BASE\n\n";

    bool all_ok = true;
    size_t index = 0;
    for (const auto &m : segments) {
        uint64_t written = 0;
        bool ok = copy_mapping(mem_fd, out_fd, m, base, output_size, &written);
        uint64_t out_offset = static_cast<uint64_t>(m.start - base);
        report << "SEGMENT[" << std::dec << index++ << "]=0x" << std::hex << m.start
               << "-0x" << m.end
               << " out_off=0x" << out_offset
               << " original_file_off=0x" << m.file_offset
               << " size=0x" << m.size()
               << " perms=" << m.perms
               << " written=0x" << written
               << " status=" << (ok ? "OK" : "PARTIAL") << "\n";
        all_ok = all_ok && ok;
    }

    fsync(out_fd);
    close(out_fd);
    close(mem_fd);
    report.close();

    if (rename(tmp.c_str(), final_path.c_str()) != 0) {
        LOGE("va dump: rename failed: %s", strerror(errno));
        unlink(tmp.c_str());
        return false;
    }

    std::ofstream base_out(base_path, std::ios::trunc);
    base_out << std::hex << base << "\n";
    base_out.close();

    LOGI("VA dump done: %s base=0x%" PRIxPTR " end=0x%" PRIxPTR " span=0x%" PRIx64,
         final_path.c_str(), base, image_end, output_size);
    LOGI("Il2CppDumper input base for libil2cpp.vadump.so: %" PRIxPTR, base);
    LOGI("VA dump report: %s", report_path.c_str());
    return all_ok;
}
