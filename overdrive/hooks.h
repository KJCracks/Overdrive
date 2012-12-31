//
//  hooks.h
//  overdrive
//

#import "interpose.h"
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <string.h>
#include <stdlib.h>
#import <unistd.h>
#import <mach/mach_traps.h>
#import <mach/mach.h>
#include <fcntl.h>
#import <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#import <mach-o/fat.h>
#import <mach-o/swap.h>
#include <limits.h>
#include <stdlib.h>
#import "dirent.h"

void * initHooks(char *symbol);
void findswaps(FILE *fp);
void oparchitecture(void *buffer, uint32_t offset);

// dyld hooks
uint32_t _overdrive_dyld_image_count(void);
const struct mach_header* _overdrive_dyld_get_image_header(uint32_t image_index);
intptr_t _overdrive_dyld_get_image_vmaddr_slide(uint32_t image_index);
const char* _overdrive_dyld_get_image_name(uint32_t image_index);
void *_overdrive_dlsym(void *handle, const char* symbol);

// ptrace hook
int _overdrive_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

// stat hook
int _overdrive_stat(const char *path, struct stat *buf);

// directory listing hooks
DIR *_overdrive_opendir(const char *path);
struct dirent *_overdrive_readdir(DIR *dir);

// file stream hooks
FILE * _overdrive_fopen(const char* path, const char* mode);
int _overdrive_fclose(FILE *stream);
size_t _overdrive_fread( void * ptr, size_t size, size_t count, FILE * stream );

int _overdrive_open(char * filename, int flags, int mode);
int _overdrive_close(int fd);
ssize_t _overdrive_read(int fd, void * ptr, size_t numbytes);
