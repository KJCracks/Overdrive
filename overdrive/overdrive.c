#include <stdio.h>
#import "overdrive.h"


int dyld_skipimage = 0;
int dyld_imagecount = 0;

__attribute__((constructor))
static void __overdrive() {
    
    struct mach_header* mach = (struct mach_header*) _dyld_get_image_header(0);
    
    uint32_t header_size = 0;
    
    kern_return_t err;
    
    struct encryption_info_command *crypt;
    struct segment_command *tseg;
    struct dylib_command *overdrive_cmd;
    
    
    // clean up some commands
    void *curloc = (void *)mach + sizeof(struct mach_header);
    for (int i=0;i<mach->ncmds;i++) {
        struct load_command *lcmd = curloc;
        if (lcmd->cmd == LC_ENCRYPTION_INFO) {
            // put the cryptid to 1
            crypt = curloc;
        } else if (lcmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = curloc;
            if (seg->fileoff == 0 && seg->filesize != 0) {
                header_size = seg->vmsize;
                tseg = curloc;
            }
        }
        if(i == mach->ncmds-1){
            overdrive_cmd = curloc;
        }
        curloc += lcmd->cmdsize;
    }
    
    
    // make __TEXT temporarily writable
    err = vm_protect(mach_task_self(), (vm_address_t)mach, header_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    // modify the load commands
    // change protection of __TEXT segment
    tseg->maxprot = tseg->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    // change cryptid
    crypt->cryptid = 1;
    
    // the last load command is the load command for overdrive, remove it
    mach->ncmds -= 1;
    mach->sizeofcmds -= overdrive_cmd->cmdsize;

    memset(overdrive_cmd, 0, overdrive_cmd->cmdsize);
    
    // change __TEXT back to read/exec only state
    err = vm_protect(mach_task_self(), (vm_address_t) mach, header_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    err = vm_protect(mach_task_self(), (vm_address_t) mach, header_size, TRUE, VM_PROT_READ | VM_PROT_EXECUTE);
    
    for (int i=0;;i++) {
        char *image = (char *) _dyld_get_image_name(i);
        if (image == NULL)
            break;
        dyld_imagecount++;
        if (strncmp(image + strlen(image) - strlen(OVERDRIVE_DYLIB_NAME), OVERDRIVE_DYLIB_NAME, strlen(OVERDRIVE_DYLIB_NAME)) == 0) {
            dyld_skipimage = i;
            break;
        }
    }
 
    // perform hooks
    interpose();
}

