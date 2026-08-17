#include "runtime_dump.h"

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
constexpr uint64_t kMaxOutputSize = 2ULL * 1024 * 1024 * 1024;

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uint64_t file_offset = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
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
        entry.executable = entry.perms.size() > 2 && entry.perms[2] == 'x';
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
    LOGE("runtime dump: mkdir %s failed: %s", out_dir, strerror(errno));
    return false;
}

bool copy_fd(int src, int dst, uint64_t size) {
    std::vector<unsigned char> buffer(kIoChunk);
    uint64_t done = 0;
    while (done < size) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), size - done));
        ssize_t got = pread(src, buffer.data(), want, static_cast<off_t>(done));
        if (got <= 0) return false;
        ssize_t wrote = pwrite(dst, buffer.data(), static_cast<size_t>(got), static_cast<off_t>(done));
        if (wrote != got) return false;
        done += static_cast<uint64_t>(got);
    }
    return true;
}

bool dump_mem_range(int mem_fd, int out_fd, const MapEntry &entry, uint64_t out_offset,
                    uint64_t max_size, uint64_t *bytes_written) {
    if (bytes_written) *bytes_written = 0;
    if (!entry.readable || entry.size() == 0 || out_offset >= max_size) return false;

    uint64_t total = std::min<uint64_t>(entry.size(), max_size - out_offset);
    std::vector<unsigned char> buffer(kIoChunk);
    uint64_t done = 0;
    while (done < total) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), total - done));
        ssize_t got = pread(mem_fd, buffer.data(), want,
                            static_cast<off_t>(entry.start + done));
        if (got <= 0) {
            LOGW("runtime dump: pread mem 0x%" PRIxPTR " failed after 0x%" PRIx64 ": %s",
                 entry.start, done, strerror(errno));
            break;
        }
        ssize_t wrote = pwrite(out_fd, buffer.data(), static_cast<size_t>(got),
                               static_cast<off_t>(out_offset + done));
        if (wrote != got) {
            LOGW("runtime dump: pwrite failed at file+0x%" PRIx64 ": %s",
                 out_offset + done, strerror(errno));
            break;
        }
        done += static_cast<uint64_t>(got);
    }
    if (bytes_written) *bytes_written = done;
    return done == total;
}

bool atomic_rename(const std::string &tmp, const std::string &final_path) {
    if (rename(tmp.c_str(), final_path.c_str()) == 0) return true;
    LOGE("runtime dump: rename %s -> %s failed: %s", tmp.c_str(), final_path.c_str(), strerror(errno));
    return false;
}

bool open_existing_file(const std::string &map_path, std::string *resolved_path,
                        struct stat *st, int *fd) {
    std::vector<std::string> candidates;
    candidates.push_back(map_path);
    const std::string media_prefix = "/data/media/0/";
    if (map_path.rfind(media_prefix, 0) == 0) {
        candidates.push_back("/storage/emulated/0/" + map_path.substr(media_prefix.size()));
    }

    for (const auto &candidate : candidates) {
        struct stat local_st{};
        if (stat(candidate.c_str(), &local_st) != 0 || local_st.st_size <= 0) continue;
        int local_fd = open(candidate.c_str(), O_RDONLY | O_CLOEXEC);
        if (local_fd < 0) continue;
        if (resolved_path) *resolved_path = candidate;
        if (st) *st = local_st;
        if (fd) *fd = local_fd;
        else close(local_fd);
        return true;
    }
    return false;
}

}  // namespace

bool copy_backing_global_metadata(const char *out_dir) {
    if (!ensure_output_dir(out_dir)) return false;
    auto maps = read_maps();
    std::string map_path;
    for (const auto &m : maps) {
        if (m.path.find("global-metadata.dat") != std::string::npos) {
            map_path = m.path;
            break;
        }
    }
    if (map_path.empty()) {
        LOGW("raw metadata: no named global-metadata.dat mapping found");
        return false;
    }

    std::string source;
    struct stat st{};
    int src = -1;
    if (!open_existing_file(map_path, &source, &st, &src)) {
        LOGW("raw metadata: backing file cannot be opened: %s", map_path.c_str());
        return false;
    }

    std::string tmp = std::string(out_dir) + "/global-metadata.raw.dat.tmp";
    std::string final_path = std::string(out_dir) + "/global-metadata.raw.dat";
    int dst = open(tmp.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (dst < 0) {
        LOGE("raw metadata: create %s failed: %s", tmp.c_str(), strerror(errno));
        close(src);
        return false;
    }

    bool ok = copy_fd(src, dst, static_cast<uint64_t>(st.st_size));
    fsync(dst);
    close(dst);
    close(src);
    if (!ok) {
        unlink(tmp.c_str());
        LOGW("raw metadata: copy failed");
        return false;
    }
    if (!atomic_rename(tmp, final_path)) {
        unlink(tmp.c_str());
        return false;
    }

    LOGI("raw metadata copied unchanged: %s <- %s size=0x%" PRIx64,
         final_path.c_str(), source.c_str(), static_cast<uint64_t>(st.st_size));
    return true;
}

bool dump_runtime_libil2cpp(const char *out_dir) {
    if (!ensure_output_dir(out_dir)) return false;

    auto maps = read_maps();
    std::vector<MapEntry> segments;
    for (const auto &m : maps) {
        if (m.readable && m.path.find("libil2cpp.so") != std::string::npos) {
            segments.push_back(m);
        }
    }
    if (segments.empty()) {
        LOGW("runtime dump: no readable libil2cpp.so mappings found");
        return false;
    }

    const MapEntry *primary_ptr = nullptr;
    for (const auto &m : segments) {
        if (m.file_offset != 0) continue;
        if (!primary_ptr || m.size() > primary_ptr->size()) primary_ptr = &m;
    }
    if (!primary_ptr) {
        primary_ptr = &*std::max_element(segments.begin(), segments.end(),
                                        [](const MapEntry &a, const MapEntry &b) {
                                            return a.size() < b.size();
                                        });
    }
    const MapEntry primary = *primary_ptr;

    std::string source = primary.path;
    struct stat st{};
    uint64_t source_size = 0;
    if (!source.empty() && stat(source.c_str(), &st) == 0 && st.st_size > 0) {
        source_size = static_cast<uint64_t>(st.st_size);
    }

    uint64_t mapped_end = 0;
    for (const auto &m : segments) {
        if (m.file_offset > kMaxOutputSize || m.size() > kMaxOutputSize - m.file_offset) continue;
        mapped_end = std::max<uint64_t>(mapped_end, m.file_offset + m.size());
    }
    uint64_t output_size = std::max<uint64_t>(source_size, mapped_end);
    if (output_size == 0 || output_size > kMaxOutputSize) {
        LOGE("runtime dump: unreasonable output size 0x%" PRIx64, output_size);
        return false;
    }

    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0) {
        LOGE("runtime dump: open /proc/self/mem failed: %s", strerror(errno));
        return false;
    }

    std::string mem_tmp = std::string(out_dir) + "/libil2cpp.memory.so.tmp";
    std::string mem_final = std::string(out_dir) + "/libil2cpp.memory.so";
    std::string merged_tmp = std::string(out_dir) + "/libil2cpp.runtime.so.tmp";
    std::string merged_final = std::string(out_dir) + "/libil2cpp.runtime.so";
    std::string report_path = std::string(out_dir) + "/runtime_dump_info.txt";

    int mem_out = open(mem_tmp.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    int merged_out = open(merged_tmp.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (mem_out < 0 || merged_out < 0) {
        LOGE("runtime dump: create output failed: %s", strerror(errno));
        if (mem_out >= 0) close(mem_out);
        if (merged_out >= 0) close(merged_out);
        close(mem_fd);
        return false;
    }
    if (ftruncate(mem_out, static_cast<off_t>(output_size)) != 0 ||
        ftruncate(merged_out, static_cast<off_t>(output_size)) != 0) {
        LOGE("runtime dump: ftruncate failed: %s", strerror(errno));
        close(mem_out); close(merged_out); close(mem_fd);
        unlink(mem_tmp.c_str()); unlink(merged_tmp.c_str());
        return false;
    }

    bool backing_copied = false;
    if (source_size > 0) {
        int src = open(source.c_str(), O_RDONLY | O_CLOEXEC);
        if (src >= 0) {
            backing_copied = copy_fd(src, merged_out, source_size);
            close(src);
        }
    }

    std::ofstream report(report_path, std::ios::trunc);
    report << "# libil2cpp runtime reconstruction\n";
    report << "SOURCE_PATH=" << source << "\n";
    report << "SOURCE_SIZE=0x" << std::hex << source_size << "\n";
    report << "OUTPUT_SIZE=0x" << std::hex << output_size << "\n";
    report << "BACKING_COPIED=" << (backing_copied ? "YES" : "NO") << "\n";
    report << "PRIMARY_MAP=0x" << std::hex << primary.start << "-0x" << primary.end
           << " file_off=0x" << primary.file_offset << " " << primary.perms << "\n\n";

    uint64_t primary_written_mem = 0, primary_written_merged = 0;
    dump_mem_range(mem_fd, mem_out, primary, primary.file_offset, output_size, &primary_written_mem);
    dump_mem_range(mem_fd, merged_out, primary, primary.file_offset, output_size, &primary_written_merged);
    report << "PRIMARY_WRITTEN_MEMORY=0x" << std::hex << primary_written_mem << "\n";
    report << "PRIMARY_WRITTEN_MERGED=0x" << std::hex << primary_written_merged << "\n";

    std::stable_sort(segments.begin(), segments.end(), [](const MapEntry &a, const MapEntry &b) {
        if (a.writable != b.writable) return !a.writable && b.writable;
        if (a.file_offset != b.file_offset) return a.file_offset < b.file_offset;
        return a.size() > b.size();
    });

    size_t index = 0;
    for (const auto &m : segments) {
        bool is_primary = m.start == primary.start && m.end == primary.end &&
                          m.file_offset == primary.file_offset;
        if (is_primary) continue;
        if (m.file_offset == primary.file_offset && m.size() <= primary.size()) {
            report << "SEGMENT[" << std::dec << index++ << "]=SKIP_DUP_PRIMARY_OFFSET 0x"
                   << std::hex << m.start << "-0x" << m.end << " size=0x" << m.size()
                   << " perms=" << m.perms << "\n";
            continue;
        }
        uint64_t wrote_mem = 0, wrote_merged = 0;
        bool ok_mem = dump_mem_range(mem_fd, mem_out, m, m.file_offset, output_size, &wrote_mem);
        bool ok_merged = dump_mem_range(mem_fd, merged_out, m, m.file_offset, output_size, &wrote_merged);
        report << "SEGMENT[" << std::dec << index++ << "]=0x" << std::hex << m.start
               << "-0x" << m.end << " file_off=0x" << m.file_offset
               << " size=0x" << m.size() << " perms=" << m.perms
               << " mem_written=0x" << wrote_mem
               << " merged_written=0x" << wrote_merged
               << " status=" << ((ok_mem && ok_merged) ? "OK" : "PARTIAL") << "\n";
    }

    fsync(mem_out);
    fsync(merged_out);
    close(mem_out);
    close(merged_out);
    close(mem_fd);
    report.close();

    bool ok_mem = atomic_rename(mem_tmp, mem_final);
    bool ok_merged = atomic_rename(merged_tmp, merged_final);
    if (!ok_mem) unlink(mem_tmp.c_str());
    if (!ok_merged) unlink(merged_tmp.c_str());

    LOGI("runtime libil2cpp dump: memory=%s merged=%s size=0x%" PRIx64,
         ok_mem ? mem_final.c_str() : "FAILED",
         ok_merged ? merged_final.c_str() : "FAILED",
         output_size);
    LOGI("runtime dump report: %s", report_path.c_str());
    return ok_mem && ok_merged;
}
