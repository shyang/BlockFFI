//
//  main.m
//  BlockFFI
//
//  Created by shaohua on 30/03/2017.
//  Copyright © 2017 syang. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#import <ffi/ffi.h>

id __NSMakeSpecialForwardingCaptureBlock(const char *signature, void (^handler)(NSInvocation *inv));

// http://clang.llvm.org/docs/Block-ABI-Apple.html
struct Block {
    void *isa;
    int flags;
    int reserved;
    void *invoke;
};

static void SetBlockImplementation(id block, void *codePtr) {
    ((__bridge struct Block *)block)->invoke = codePtr;
}

static void Callback(ffi_cif *cif, void *ret, void **args, void *user_data) {
    // 此处实现 callback 逻辑，所有 block 都会回调到这里
    void *block = *(void **)args[0];
    void *obj = *(void **)args[1];
    NSUInteger idx = *(NSUInteger *)args[2];
    BOOL *stop = *(BOOL **)args[3];
    NSLog(@"callback: %@ %@ %u %p", block, obj, idx, stop);
}

int main(int argc, char * argv[]) {
    // -[NSArray enumerateObjectsUsingBlock:] 的第一个参数是一个 block，其签名为：
    // void (^)(id obj, NSUInteger idx, BOOL *stop)
    // 实际加上隐含的第一个参数，它共需要 4 个参数，返回 void，Type string 为：v@?@Q^B
    void *codePtr = NULL;
    int nargs = 4;
    void *user_data = NULL; // 可用于传递 self 等

    ffi_type **args = malloc(nargs * sizeof(*args));
    ffi_type *ret;

    // 按 v@?@Q^B 来填充结构体
    args[0] = &ffi_type_pointer;
    args[1] = &ffi_type_pointer;
#if __LP64__
    args[2] = &ffi_type_uint64;
#else
    args[2] = &ffi_type_uint32;
#endif
    args[3] = &ffi_type_pointer;
    ret = &ffi_type_void;

    ffi_cif *cif = malloc(sizeof(*cif)); // call interface
    ffi_status status = ffi_prep_cif(cif, FFI_DEFAULT_ABI, nargs, ret, args);
    assert(status == FFI_OK);

    ffi_closure *closure = ffi_closure_alloc(sizeof(*closure), &codePtr);
    status = ffi_prep_closure_loc(closure, cif, Callback, user_data, codePtr);
    assert(status == FFI_OK);

    id block = ^{
        assert(0); // should never reach here

        // pass some references into the block as upvalues
        // which will be removed when this block dealloc's
        // [aLocalObject anyMessage];
    };
    SetBlockImplementation(block, codePtr);

    // 使用创建的 block
    NSArray *arr = @[@"a", @"b", @"c"];
    [arr enumerateObjectsUsingBlock:block];

    // another solution
    id proxy = __NSMakeSpecialForwardingCaptureBlock("v@?@Q^B", ^(NSInvocation *inv) {
        id obj = nil;
        [inv getArgument:&obj atIndex:1];

        NSUInteger idx = 0;
        [inv getArgument:&idx atIndex:2];

        NSLog(@"%@: obj %@, idx: %u", inv, obj, idx);
    });
    [arr enumerateObjectsUsingBlock:proxy];
}
