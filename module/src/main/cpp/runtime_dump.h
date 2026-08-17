#ifndef ZYGISK_IL2CPPDUMPER_RUNTIME_DUMP_H
#define ZYGISK_IL2CPPDUMPER_RUNTIME_DUMP_H

bool dump_runtime_libil2cpp(const char *out_dir);
bool copy_backing_global_metadata(const char *out_dir);

#endif
