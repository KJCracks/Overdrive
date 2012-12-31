//
//  descriptors.h
//  overdrive
//
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface descriptors : NSObject {
@private
    NSMutableArray *_streamfiledescriptors;
    NSMutableArray *_openfiledescriptors;
@public
    NSRecursiveLock *sfLock;
    NSRecursiveLock *opLock;
}
+(descriptors*)sharedInstance;

-(void)setStreamfiledescriptors:(NSMutableArray *)streamfiledescriptors;
-(NSMutableArray*)requeststreamfiledescriptors;
-(void)closestreamfiledescriptors;
-(void)setOpenfiledescriptors:(NSMutableArray *)openfiledescriptors;
-(NSMutableArray*)requestopenfiledescriptors;
-(void)closeopenfiledescriptors;

@property (getter = requeststreamfiledescriptors , retain) NSMutableArray *streamfiledescriptors;
@property (getter = requestopenfiledescriptors, retain) NSMutableArray *openfiledescriptors;
@end
