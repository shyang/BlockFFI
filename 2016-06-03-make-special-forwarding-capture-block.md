---
layout: post
title: __NSMakeSpecialForwardingCaptureBlock()
---

## 概述
__NSMakeSpecialForwardingCaptureBlock 是一个私有函数，代码在 CoreFoundation 之中：

```console
$ nm /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation | grep NSMakeSpecialForwardingCaptureBlock
00000000000bb4f0 T ___NSMakeSpecialForwardingCaptureBlock
000000000015b6c0 t _____NSMakeSpecialForwardingCaptureBlock_block_invoke
```

它能够动态创建一个 capture block，所有对该 capture block 的调用，都将被包装成一个 NSInvocation 对象，供一个统一的 handler 解析：

`id __NSMakeSpecialForwardingCaptureBlock(const char *signature, void (^handler)(NSInvocation *inv));`

## 示例
只适用于 64 位机器，因为 `"v@?@Q^B"` 是 64 位专用的。32 位下该 block 的 signature 需修改为 `v@?@I^c`

```c
id proxy = __NSMakeSpecialForwardingCaptureBlock("v@?@Q^B", ^(NSInvocation *inv) {
    id obj = nil;
    [inv getArgument:&obj atIndex:1];

    NSUInteger idx = 0;
    [inv getArgument:&idx atIndex:2];

    NSLog(@"%@: obj %@, idx: %u", inv, obj, idx);
});
NSArray *arr = @[@"a", @"b", @"c"];
[arr enumerateObjectsUsingBlock:proxy];
    
```
log 输出的是：

```
<NSBlockInvocation: 0x7f9cb3f299c0>: obj a, idx: 0
<NSBlockInvocation: 0x7f9cb3f299c0>: obj b, idx: 1
<NSBlockInvocation: 0x7f9cb3d67ac0>: obj c, idx: 2
```

也就是说 enumerateObjectsUsingBlock: 把执行权交给了那个 handler，后者用 getArgument:atIndex: 与 setReturnValue: 来模拟原 block 参数的任务。

NSBlockInvocation 是一个精简的 NSInvocation，只是用来传递输入参数与返回值。


## 实现原理

反编译 CoreFoundation 的 x86_64 版本可得到：

```c
int ___NSMakeSpecialForwardingCaptureBlock(int arg0, int arg1, int arg2, int arg3, int arg4, int arg5) {
    r9 = arg5;
    r8 = arg4;
    rcx = arg3;
    rdx = arg2;
    r15 = arg1;
    r14 = arg0;
    rbx = 0x0;
    if ((r14 == 0x0) || (r15 == 0x0)) goto loc_bb636;

loc_bb519:
    rax = ___block_descriptor_tmp;
    if ((0xc2000000 & 0x40000000) == 0x0) goto loc_bb646;

loc_bb559:
    if ((0xc2000000 & 0x2000000) == 0x0) goto loc_bb649;

loc_bb566:
    rax = strnlen(r14, 0x400);
    if (rax == 0x400) {
            rbx = 0x0;
            _CFLog(0x3, @"Error: Attempt to make special forwarding block with a signature that is too large.", rdx, rcx, r8, r9, stack[2048]);
    }
    else {
            rbx = calloc(0x1, rax + 0x59);                 // 注1
            *rbx = __NSConcreteMallocBlock;
            *(int32_t *)(rbx + 0x8) = 0x43000002;
            *(rbx + 0x18) = rbx + 0x28;
            *(rbx + 0x10) = ___forwarding_prep_b___;
            *(rbx + 0x20) = r15;                           // 注2
            *(int128_t *)(rbx + 0x28) = intrinsic_movdqu(*(int128_t *)(rbx + 0x28), intrinsic_pslldq(zero_extend_64(0x60), 0x8));
            *(int128_t *)(rbx + 0x38) = intrinsic_movdqu(*(int128_t *)(rbx + 0x38), intrinsic_punpcklqdq(zero_extend_64(___copy_helper_block_), zero_extend_64(___destroy_helper_block_)));
            *(rbx + 0x48) = rbx + 0x58;
            *(rbx + 0x50) = 0x100;
            __strlcpy_chk(rbx + 0x58, r14, rax + 0x1, 0xffffffffffffffff);
            (*(rbx + 0x38))(rbx, __NSConcreteStackBlock);
    }
    goto loc_bb636;

loc_bb636:
    rax = rbx;
    return rax;

loc_bb649:
    asm{ int3        };
    return rax;

loc_bb646:
    asm{ int3        };
    return rax;
}

```

注1: 此处在构造一个 capture block，后面多条 assign 语句都是在填充（即初始化）这个对象。

注2：根据[结构定义](https://clang.llvm.org/docs/Block-ABI-Apple.html)，r15 是一个被 capture block 使用到的导入变量，即 handler。

可以看出这个函数主要工作就是创建这样一个 Block 并返回（rax中），其实现在 `___forwarding_prep_b___` 之中


```asm
                     ___forwarding_prep_b___:
00000000000bb660         push       rbp                                         ; XREF=___NSMakeSpecialForwardingCaptureBlock+214
00000000000bb661         mov        rbp, rsp
00000000000bb664         sub        rsp, 0xd0
00000000000bb66b         mov        qword [ss:rsp+0xb0], rax
00000000000bb673         movq       qword [ss:rsp+0xa0], xmm7
00000000000bb67c         movq       qword [ss:rsp+0x90], xmm6
00000000000bb685         movq       qword [ss:rsp+0x80], xmm5
00000000000bb68e         movq       qword [ss:rsp+0x70], xmm4
00000000000bb694         movq       qword [ss:rsp+0x60], xmm3
00000000000bb69a         movq       qword [ss:rsp+0x50], xmm2
00000000000bb6a0         movq       qword [ss:rsp+0x40], xmm1
00000000000bb6a6         movq       qword [ss:rsp+0x30], xmm0
00000000000bb6ac         mov        qword [ss:rsp+0x28], r9
00000000000bb6b1         mov        qword [ss:rsp+0x20], r8
00000000000bb6b6         mov        qword [ss:rsp+0x18], rcx
00000000000bb6bb         mov        qword [ss:rsp+0x10], rdx
00000000000bb6c0         mov        qword [ss:rsp+0x8], rsi
00000000000bb6c5         mov        qword [ss:rsp], rdi
00000000000bb6c9         mov        rdi, rsp                                    ; argument #1 for method ___block_forwarding___
00000000000bb6cc         call       ___block_forwarding___
00000000000bb6d1         mov        rsp, rbp
00000000000bb6d4         pop        rbp
00000000000bb6d5         ret        
                        ; endp
00000000000bb6d6         nop        
00000000000bb6d7         nop        word [ds:rax+rax]
```

它将可以用于参数传递的寄存器全部逆序压栈后，rsp 就是 frame 的起始！！！ 提供给 `[NSBlockInvocation _invocationWithMethodSignature:frame:]`，然后调用 `___block_forwarding___`

```c
void ___block_forwarding___(int arg0) {
    rbx = arg0;
    r14 = *rbx;
    if (strncmp(class_getName(object_getClass(r14)), "_NSZombie_", 0xa) != 0x0) {
            rax = _Block_signature(r14);
            if (rax != 0x0) {
                    rbx = [NSBlockInvocation _invocationWithMethodSignature:[NSMethodSignature signatureWithObjCTypes:rax] frame:rbx];
                    [rbx setTarget:0x0];
                    rdi = *(r14 + 0x20);            // 注1
                    if (rdi != 0x0) {
                            rax = *(rdi + 0x10);    // 注2
                            (rax)();
                    }
                    else {
                            asm{ int3        };
                    }
            }
            else {
                    _CFLog(0x4, @"*** NSBlockInvocation: Block %p does not have a type signature -- abort", r14, rcx, r8, r9, stack[2048]);
                    asm{ int3        };
            }
    }
    else {
            if (*(int8_t *)___CFOASafe != 0x0) {
                    ___CFRecordAllocationEvent();
            }
            _CFLog(0x3, @"*** NSBlockInvocation: invocation of deallocated Block instance %p", r14, 0x0, 0x0, r9, stack[2048]);
            asm{ int3        };
    }
    return;
}
```
注1：引用刚才的导入变量作为 arg0，即 handler。

注2：这个偏移是 invoke 指针，即 capture block 跳转到 handler。

其中的核心代码，利用参数 signature 和所有寄存器组成的 frame 内容，构造一个 NSBlockInvocation 对象。


#### PS1 参数的顺序

[Let's Build NSInvocation, Part I](https://www.mikeash.com/pyblog/friday-qa-2013-03-08-lets-build-nsinvocation-part-i.html)

`rdi, rsi, rdx, rcx, r8, r9, (rsp), (rsp+0x8), (rsp+0x10), ...`

#### PS2

`__forwarding_prep_b___` 与 `___forwarding_prep_1___` 压栈的方式完全相同。功能更简单易懂些。


#### PS3

[Block 的结构](https://clang.llvm.org/docs/Block-ABI-Apple.html)

```c
struct {
  void *isa;     // 32: 0x0, 64:  0x0
  int flags;     // 32: 0x4, 64:  0x8
  int reserved;
  void *invoke;  // 32: 0xc, 64: 0x10
}
```
32 位模拟器、arm offset 12 字节。64 位模拟器、arm offset 16 字节。 