//
//  descriptors.m
//  overdrive
//
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import "descriptors.h"

static descriptors *sharedInstance = nil;

@implementation descriptors


+(descriptors*)sharedInstance {
    @synchronized(self) {
        if (!sharedInstance) {
            sharedInstance = [[descriptors alloc] init];
            sharedInstance->_streamfiledescriptors = [[NSMutableArray alloc] init];
            sharedInstance->_openfiledescriptors = [[NSMutableArray alloc] init];
            sharedInstance->sfLock = [[NSRecursiveLock alloc] init];
            
            sharedInstance->opLock = [[NSRecursiveLock alloc] init];
        }
        
    }
    return sharedInstance;
}

-(void)setStreamfiledescriptors:(NSMutableArray *)streamfiledescriptors {
    //SHITS NOT REALLY NEEDED....
    [sfLock lock];
    [_streamfiledescriptors release];
    _streamfiledescriptors = [streamfiledescriptors retain];
    [sfLock unlock];
    
}

-(NSMutableArray*)requeststreamfiledescriptors {
    [sfLock lock];
    return [_streamfiledescriptors retain];
}

-(void)closestreamfiledescriptors {
    [_streamfiledescriptors release];
    [sfLock unlock];
}

-(void)setOpenfiledescriptors:(NSMutableArray *)openfiledescriptors {
    //SHITS NOT REALLY NEEDED....
    [opLock lock];
    [_openfiledescriptors release];
    _openfiledescriptors = [openfiledescriptors retain];
    [sfLock unlock];
}

-(NSMutableArray*)requestopenfiledescriptors {
    [opLock lock];
    return [_openfiledescriptors retain];
}

-(void)closeopenfiledescriptors {
    [_openfiledescriptors release];
    [opLock unlock];
}

-(void)dealloc {
    [super dealloc];
    [_streamfiledescriptors release];
    [_openfiledescriptors release];
    [opLock release];
    [sfLock release];
}
@end

