//
//  hooks.m
//  overdrive
//

#import "hooks.h"
#import "interpose.h"
#import "descriptors.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#import <Foundation/Foundation.h>



@interface hooks : NSObject

void * initHooks(char *symbol);
void findswaps(FILE *fp);
void oparchitecture(void *buffer, uint32_t offset);
@end

@implementation hooks

// list of active file streams
//NSMutableArray *streamfiledescriptors;
//NSMutableArray *openfiledescriptors;

// are the *open() hooks enabled? we don't want nested hooking, so we can disable this later
static int open_hook_enabled = 1;

// a list of things we need to swap when a file is read
NSMutableArray *localbinary_swaps = nil;



#define HOOK(val) if (!open_hook_enabled) {return val;} else { open_hook_enabled = 0; val;};
#define UNHOOK() open_hook_enabled = 1;

#define descriptorsInstance() [descriptors sharedInstance]
#define requestStreamFileDescriptors() [descriptors sharedInstance].requeststreamfiledescriptors
#define closeStreamFileDescriptors() [[descriptors sharedInstance] closestreamfiledescriptors]

#define requestOpenFileDescriptors() [descriptors sharedInstance].requestopenfiledescriptors
#define closeOpenFileDescriptors() [[descriptors sharedInstance] closeopenfiledescriptors]

#define addStreamFileDescriptor(val) [[descriptors sharedInstance].requeststreamfiledescriptors addObject:[NSValue valueWithPointer:val]]; [[descriptors sharedInstance] closestreamfiledescriptors]
#define addOpenFileDescriptor(val) [[descriptors sharedInstance].requestopenfiledescriptors addObject:[NSValue valueWithPointer:val]]; [[descriptors sharedInstance] closeopenfiledescriptors]

void * initHooks(char *symbol) {
    // dyld hooks
    if (!strcmp(symbol, "_dyld_image_count")) return _overdrive_dyld_image_count;
    if (!strcmp(symbol, "_dyld_get_image_header")) return _overdrive_dyld_get_image_header;
    if (!strcmp(symbol, "_dyld_get_image_vmaddr_slide")) return _overdrive_dyld_get_image_vmaddr_slide;
    if (!strcmp(symbol, "_dyld_get_image_name")) return _overdrive_dyld_get_image_name;
    if (!strcmp(symbol, "dlsym")) return _overdrive_dlsym;
    
    // ptrace hook
    if (!strcmp(symbol, "ptrace")) return _overdrive_ptrace;
    
    // stat hook
    if (!strcmp(symbol, "stat"))   return _overdrive_stat;
    
    // directory listing hooks
    if (!strcmp(symbol, "opendir")) return _overdrive_opendir;
    if (!strcmp(symbol, "readdir")) return _overdrive_readdir;
    
    // file stream hooks
    if (!strcmp(symbol, "fopen")) return _overdrive_fopen;
    if (!strcmp(symbol, "fclose")) return _overdrive_fclose;
    if (!strcmp(symbol, "fread"))   return _overdrive_fread;
    
    if (!strcmp(symbol, "open")) return _overdrive_open;
    if (!strcmp(symbol, "read")) return _overdrive_read;
    if (!strcmp(symbol, "close")) return _overdrive_close;
    
    return NULL;
}

void findswaps(FILE *fp) {
    fseek(fp, 0, SEEK_END);
    BOOL isFat = FALSE;
    uint32_t sizeOfBinary = ftell(fp);
    void *buffer = malloc(sizeOfBinary); // allocate enough space for the entire local binary
    fseek(fp, 0, SEEK_SET);
    fread(buffer, sizeOfBinary, 1, fp);
    fseek(fp, 0, SEEK_SET);
    
    uint32_t magic = *(uint32_t*)buffer;
    switch (magic) {
        case MH_MAGIC:
            break;
        case MH_CIGAM:
            break;
        case FAT_MAGIC:
            isFat = TRUE;
            break;
        case FAT_CIGAM:
            isFat = TRUE;
            break;
        default:
            NSLog(@"Not a mach-o file (wtf?)");
            return;
    }
    
    if (isFat) {
        // this is a fat binary, iterate over each architecture
        struct fat_arch * faPtr = (struct fat_arch*)((char*)buffer+sizeof(struct fat_header));
        struct fat_header fh = *(struct fat_header*)buffer;
        fh.nfat_arch = CFSwapInt32(fh.nfat_arch);
        
        for (int i=0;i < fh.nfat_arch;i++) {
            oparchitecture(buffer, CFSwapInt32(faPtr->offset));
            faPtr++;
        }
    } else {
        // this is a thin binary, operate over this architecture
        oparchitecture(buffer, 0);
    }
    
    free(buffer);
}

void oparchitecture(void *buffer, uint32_t offset) {
    struct mach_header *mach = buffer + offset;
    
    uint32_t newmach_ncmds = mach->ncmds - 1;
    
    [localbinary_swaps addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                  // the location in the file
                                  [NSNumber numberWithInt:((void *)&mach->ncmds - buffer)], @"start",
                                  // the replacement itself
                                  [NSData dataWithBytes:&newmach_ncmds length:sizeof(uint32_t)], @"replacewith"
                                  , nil]];
    
    void *curloc = (void *)mach + sizeof(struct mach_header);
    struct load_command *lc;
    for (int i=0;i<mach->ncmds;i++) {
        lc = curloc;
        if (lc->cmd == LC_ENCRYPTION_INFO) {
            struct encryption_info_command *crypt = (struct encryption_info_command *)lc;
            uint32_t newcryptid = 1;
            [localbinary_swaps addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                          // the location in the file
                                          [NSNumber numberWithInt:((void *)&crypt->cryptid - buffer)], @"start",
                                          // the replacement itself
                                          [NSData dataWithBytes:&newcryptid length:sizeof(uint32_t)], @"replacewith"
                                          , nil]];
        } else if (lc->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)lc;
            vm_prot_t newprot = VM_PROT_READ | VM_PROT_EXECUTE;
            if (seg->fileoff == 0 && seg->filesize > 0) {
                [localbinary_swaps addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                              // the location in the file
                                              [NSNumber numberWithInt:((void *)&seg->initprot - buffer)], @"start",
                                              // the replacement itself
                                              [NSData dataWithBytes:&newprot length:sizeof(vm_prot_t)], @"replacewith"
                                              , nil]];
                
                [localbinary_swaps addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                              // the location in the file
                                              [NSNumber numberWithInt:((void *)&seg->maxprot - buffer)], @"start",
                                              // the replacement itself
                                              [NSData dataWithBytes:&newprot length:sizeof(vm_prot_t)], @"replacewith"
                                              , nil]];
            }
        }
        
        curloc += lc->cmdsize;
    }
    // the last load command is the one we need to hide
    uint32_t newcmdsize = mach->sizeofcmds - lc->cmdsize;
    [localbinary_swaps addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                  // the location in the file
                                  [NSNumber numberWithInt:((void *)&mach->sizeofcmds - buffer)], @"start",
                                  // the replacement itself
                                  [NSData dataWithBytes:&newcmdsize length:sizeof(uint32_t)], @"replacewith"
                                  , nil]];
    
    void *zeros = malloc(lc->cmdsize); // zeros
    [localbinary_swaps addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                  // the location in the file
                                  [NSNumber numberWithInt:((void *)lc - buffer)], @"start",
                                  // the replacement itself
                                  [NSData dataWithBytes:zeros length:lc->cmdsize], @"replacewith"
                                  , nil]];
}

// dyld hooks
uint32_t _overdrive_dyld_image_count(void) {
    return _dyld_image_count() - 1;
}

const struct mach_header* _overdrive_dyld_get_image_header(uint32_t image_index) {
    if (image_index >= dyld_skipimage)
        return _dyld_get_image_header(image_index + 1);
    else
        return _dyld_get_image_header(image_index);
}

intptr_t _overdrive_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if (image_index >= dyld_skipimage)
        return _dyld_get_image_vmaddr_slide(image_index + 1);
    else
        return _dyld_get_image_vmaddr_slide(image_index);
}
const char* _overdrive_dyld_get_image_name(uint32_t image_index) {
    if (image_index >= dyld_skipimage)
        return _dyld_get_image_name(image_index + 1);
    else
        return _dyld_get_image_name(image_index);
}

void *_overdrive_dlsym(void *handle, const char* symbol) {
    void *loc = NULL;
    loc = initHooks((char *) symbol);
    if (loc == NULL)
        return dlsym(handle, symbol);
    else
        return loc;
}

// ptrace hook
int _overdrive_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data) {
    int retVal;
    if (_request == PT_DENY_ATTACH || _request == PT_TRACEME) {
        return 0;
    }
    else {
        void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
        ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
        retVal = ptrace_ptr(_request, _pid, _addr, _data);
        dlclose(handle);
    }
    
    return retVal;
}

// stat hook
int _overdrive_stat(const char *path, struct stat *buf) {
    int ret;
    HOOK(ret = stat(path, buf));
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSString *string = [[NSString alloc] initWithCString:path encoding:NSUTF8StringEncoding];
    if([string rangeOfString:@"SC_Info"].location != NSNotFound) {
        path = [[string stringByReplacingOccurrencesOfString:@"SC_Info" withString:@"SF_Info"] UTF8String];
    } else if ([string rangeOfString:@"SF_Info"].location != NSNotFound) {
        path = "/__OVERDRIVE"; // file that doesn't exist (and cannot)
    }
    
    ret = stat(path, buf);
    [string release];
    [pool drain];
    
    UNHOOK();
    return ret;
}

// directory listing hooks
DIR *_overdrive_opendir(const char *path) {
    DIR *ret;
    HOOK(ret = opendir(path));
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSString *string = [[NSString alloc] initWithCString:path encoding:NSUTF8StringEncoding];
    if([string rangeOfString:@"SC_Info"].location != NSNotFound) {
        path = [[string stringByReplacingOccurrencesOfString:@"SC_Info" withString:@"SF_Info"] UTF8String];
        closedir(ret);
        ret = opendir(path);
    } else if ([string rangeOfString:@"SF_Info"].location != NSNotFound) {
        path = "/__OVERDRIVE"; // file that doesn't exist (and cannot)
        closedir(ret);
        ret = opendir(path);
    }
    
    [string release];
    [pool drain];
    
    UNHOOK();
    return ret;
}

struct dirent *_overdrive_readdir(DIR *dir) {
    struct dirent *read;
    HOOK(read = readdir(dir));    
    
    if (!read)
        goto end;
    
    if (!strncmp("SF_Info", read->d_name, 7)) {
        read->d_name[1] = 'C';
    }

end:
    UNHOOK();
    return read;
}

// file stream hooks



FILE * _overdrive_fopen(const char* path, const char* mode) {
    FILE *fp;
    HOOK(fp = fopen(path, mode));

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    if (!fp)
        goto end;
    
    char realpath_buf[PATH_MAX];
    char realpath_myself_buf[PATH_MAX];
    realpath(path, realpath_buf);
    realpath(_dyld_get_image_name(0), realpath_myself_buf);
    
    NSString *myself = [NSString stringWithCString:realpath_myself_buf encoding:NSUTF8StringEncoding];
    NSString *str = [NSString stringWithCString:realpath_buf encoding:NSUTF8StringEncoding];
    
    if([str rangeOfString:@"SC_Info"].location != NSNotFound) { // DEV IS CHECKING SC_INFO
        fclose(fp);
        fp = fopen([[str stringByReplacingOccurrencesOfString:@"SC_Info" withString:@"SF_Info"] UTF8String], mode);
        goto end;
    } else if([str rangeOfString:@"SF_Info"].location != NSNotFound) { // DEV IS CHECKING SF_INFO (WHY?)
        fclose(fp);
        fp = NULL;
        goto end;
    } else if([str isEqualToString:myself]) { // are we fopening main binary?
        if (localbinary_swaps == nil) {
            localbinary_swaps = [[NSMutableArray alloc] init];
            findswaps(fp);
        }

        //[streamfiledescriptors addObject:[NSValue valueWithPointer:fp]];
        //[descriptorInstance().streamfiledescriptors addObject:[NSValue valueWithPointer:fp]];
        //NSMutableArray *sfd = descriptorInstance().requeststreamfiledescriptors; //lock
        addStreamFileDescriptor(fp);
        //[sfd addObject:[NSValue valueWithPointer:fp]];
        //descriptorInstance().closestreamfiledescriptors; //unlock
    }
    
end:
    [pool drain];
    UNHOOK();
    return fp;
}

int _overdrive_open(char * filename, int flags, int mode) {
    int ret;
    HOOK(ret = open(filename, flags, mode));
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    if (ret < 0)
        goto end;
    
    char realpath_buf[PATH_MAX];
    char realpath_myself_buf[PATH_MAX];
    realpath(filename, realpath_buf);
    realpath(_dyld_get_image_name(0), realpath_myself_buf);
    
    NSString *myself = [NSString stringWithCString:realpath_myself_buf encoding:NSUTF8StringEncoding];
    NSString *str = [NSString stringWithCString:realpath_buf encoding:NSUTF8StringEncoding];
    
    if([str rangeOfString:@"SC_Info"].location != NSNotFound) { // DEV IS CHECKING SC_INFO
        close(ret);
        ret = open([[str stringByReplacingOccurrencesOfString:@"SC_Info" withString:@"SF_Info"] UTF8String], flags, mode);
        goto end;
    } else if([str rangeOfString:@"SF_Info"].location != NSNotFound) { // DEV IS CHECKING SF_INFO (WHY?)
        close(ret);
        ret = -1;
        goto end;
    } else if([str isEqualToString:myself]) { // are we opening the main binary?
        if (localbinary_swaps == nil) {
            // prepare to perform swaps
            localbinary_swaps = [[NSMutableArray alloc] init];
            FILE *fp = fopen(filename, "r");
            findswaps(fp);
            fclose(fp);
        }
        
        //[openfiledescriptors addObject:[NSValue valueWithPointer:(void *)ret]];
        addOpenFileDescriptor((void*)ret);
    }
    
end:
    [pool drain];
    UNHOOK();
    return ret;
}

int _overdrive_fclose(FILE *stream) {
    int ret;
    HOOK(ret = fclose(stream));

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableArray *streamfiledescriptors = requestStreamFileDescriptors();//[descriptors sharedInstance].requeststreamfiledescriptors;
    if (![streamfiledescriptors count])
        goto end;
    
    for (int i=0; i < [[descriptors sharedInstance].streamfiledescriptors count];i++) {
        // is the given fd in our list?
        FILE *wfd = [[streamfiledescriptors objectAtIndex:i] pointerValue];
        if (wfd == stream) {
            // we have a match
            [streamfiledescriptors removeObjectAtIndex:i];
            break;
        }
    }

end:
    closeStreamFileDescriptors(); //[[descriptors sharedInstance] closeopenfiledescriptors];
    [pool drain];
    UNHOOK();
    return ret;
}

int _overdrive_close(int fd) {
    int ret;
    HOOK(ret = close(fd));

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableArray *openfiledescriptors = requestOpenFileDescriptors();
    if (![openfiledescriptors count])
        goto end;
    
    for (int i=0; i < [openfiledescriptors count];i++) {
        // is the given fd in our list?
        int wfd = (int) [[openfiledescriptors objectAtIndex:i] pointerValue];
        if (wfd == fd) {
            // we have a match
            [openfiledescriptors removeObjectAtIndex:i];
            break;
        }
    }
    
end:
    [pool drain];
    closeOpenFileDescriptors();
    UNHOOK();
    return ret;
}

size_t _overdrive_fread( void * ptr, size_t size, size_t count, FILE * stream ) {
    // store the old position
    uint32_t oldpos = ftell(stream);
    
    size_t returnVal;
    HOOK(returnVal = fread(ptr, size, count, stream));
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    NSMutableArray *streamfiledescriptors = requestStreamFileDescriptors();
    
    if (![streamfiledescriptors count])
        goto end;
    
    for (int i=0; i < [streamfiledescriptors count];i++) {
        // is the given fd in our list?
        FILE *wfd = [[streamfiledescriptors objectAtIndex:i] pointerValue];
        
        if (wfd == stream) {
            // we have a match
            uint32_t realsize = size * count;
            
            NSMutableDictionary *swap;
            for (int y=0; y<[localbinary_swaps count];y++) {
                swap = [localbinary_swaps objectAtIndex:y];
                
                void *data = (void *)[(NSData *)[swap objectForKey:@"replacewith"] bytes];
                uint32_t datasize = [(NSData *)[swap objectForKey:@"replacewith"] length];
                uint32_t start = [(NSNumber *)[swap objectForKey:@"start"] integerValue];
                
                // check the upper and lower bounds of the replacement
                if (oldpos <= start && (oldpos + realsize) >= (start + datasize)) {
                    void *p = ptr + (start - oldpos);
                    
                    // replace the data
                    memcpy(p, data, datasize);
                }
            }
            
            break;
        }
    }
    
end:
    closeStreamFileDescriptors();
    [pool drain];
    UNHOOK();
    return returnVal;
}

ssize_t _overdrive_read(int fd, void * ptr, size_t numbytes) {
    ssize_t ret;
    // store the old position
    uint32_t oldpos = lseek(fd, 0, SEEK_CUR);
    
    HOOK(ret = read(fd, ptr, numbytes));
    
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableArray *openfiledescriptors = requestOpenFileDescriptors();
    if (![openfiledescriptors count])
        goto end;
    
    for (int i=0; i < [openfiledescriptors count];i++) {
        // is the given fd in our list?
        int wfd = (int) [[openfiledescriptors objectAtIndex:i] pointerValue];
        if (wfd == fd) {
            // we have a match
            uint32_t realsize = numbytes;
            NSMutableDictionary *swap;
            for (int y=0; y<[localbinary_swaps count];y++) {
                swap = [localbinary_swaps objectAtIndex:y];
                
                void *data = (void *)[(NSData *)[swap objectForKey:@"replacewith"] bytes];
                uint32_t datasize = [(NSData *)[swap objectForKey:@"replacewith"] length];
                uint32_t start = [(NSNumber *)[swap objectForKey:@"start"] integerValue];
                
                // check the upper and lower bounds of the replacement
                if (oldpos <= start && (oldpos + realsize) >= (start + datasize)) {
                    void *p = ptr + (start - oldpos);
                    
                    // replace the data
                    memcpy(p, data, datasize);
                }
            }
            
            break;
        }
    }
    
end:
    closeOpenFileDescriptors();
    [pool drain];
    UNHOOK();
    return ret;
}

@end
