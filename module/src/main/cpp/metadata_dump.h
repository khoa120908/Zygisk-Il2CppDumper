#ifndef ZYGISK_IL2CPPDUMPER_METADATA_DUMP_H
#define ZYGISK_IL2CPPDUMPER_METADATA_DUMP_H

// Write the current libil2cpp/global-metadata memory map ranges to files/dump_info.txt.
// Safe to call even when IL2CPP exports are stripped.
bool save_runtime_ranges(const char *out_dir);

// Search readable data mappings for a standard IL2CPP global-metadata header.
// On success writes files/global-metadata.dat and refreshes files/dump_info.txt.
bool dump_global_metadata(const char *out_dir);

#endif // ZYGISK_IL2CPPDUMPER_METADATA_DUMP_H
