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
#import "hooks.h"

// overdrive constructor stuff
#define OVERDRIVE_DYLIB_NAME "overdrive.dylib"

int dyld_skipimage;
int dyld_imagecount;

#if !defined (PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#define PT_TRACEME 0
#endif

typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);