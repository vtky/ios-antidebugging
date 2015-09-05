//
//  main.m
//  antidebugging
//
//  Created by Vincent Tan on 7/8/15.
//  Copyright (c) 2015 Vincent Tan. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

// For debugger_ptrace. Ref: https://www.theiphonewiki.com/wiki/Bugging_Debuggers
#import <dlfcn.h>
#import <sys/types.h>

// For debugger_sysctl
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>

// For ioctl
#include <termios.h>
#include <sys/ioctl.h>

// For task_get_exception_ports
#include <mach/task.h>
#include <mach/mach_init.h>




typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif  // !defined(PT_DENY_ATTACH)

/*!
 @brief This is the basic ptrace functionality.
 @link http://www.coredump.gr/articles/ios-anti-debugging-protections-part-1/
 */
void debugger_ptrace()
{
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}




/*!
 @brief This function uses sysctl to check for attached debuggers.
 @link https://developer.apple.com/library/mac/qa/qa1361/_index.html
 @link http://www.coredump.gr/articles/ios-anti-debugging-protections-part-2/
 */
static bool debugger_sysctl(void)
// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
{
    int mib[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    // Initialize the flags so that, if sysctl fails for some bizarre
    // reason, we get a predictable result.
    
    info.kp_proc.p_flag = 0;
    
    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    // Call sysctl.
    
    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == -1)
    {
        perror("perror sysctl");
        exit(-1);
    }
    
    // We're being debugged if the P_TRACED flag is set.
    
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}






int main(int argc, char * argv[]) {

    // If enabled the program should exit with code 055 in GDB
    // Program exited with code 055.
    debugger_ptrace();
    NSLog(@"Bypassed ptrace()");
    
    // If enabled the program should exit with code 0377 in GDB
    // Program exited with code 0377.
    if (debugger_sysctl())
    {
        return -1;
    } else {
        NSLog(@"Bypassed sysctl()");
    }
    
    // Another way of calling ptrace.
    // Ref: https://www.theiphonewiki.com/wiki/Kernel_Syscalls
    syscall(26, 31, 0, 0);
    NSLog(@"Bypassed syscall()");
    
    
    // Ref: https://reverse.put.as/wp-content/uploads/2012/07/Secuinside-2012-Presentation.pdf
    struct ios_execp_info
    {
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        mach_msg_type_number_t count;
    };
    struct ios_execp_info *info = malloc(sizeof(struct ios_execp_info));
    kern_return_t kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, info->masks, &info->count, info->ports, info->behaviors, info->flavors);
    
    for (int i = 0; i < info->count; i++)
    {
        if (info->ports[i] !=0 || info->flavors[i] == THREAD_STATE_NONE)
        {
            NSLog(@"Being debugged... task_get_exception_ports");
        } else {
            NSLog(@"task_get_exception_ports bypassed");
        }
    }
    
    
    // Another way of figuring out if LLDB is attached.
    if (isatty(1)) {
        NSLog(@"Being Debugged isatty");
    } else {
        NSLog(@"isatty() bypassed");
    }
    
    // Yet another way of figuring out if LLDB is attached.
    if (!ioctl(1, TIOCGWINSZ)) {
        NSLog(@"Being Debugged ioctl");
    } else {
        NSLog(@"ioctl bypassed");
    }

    
    
    // Everything above relies on libraries. It is easy enough to hook these libraries and return the required
    // result to bypass those checks. So here it is implemented in ARM assembly. Not very fun to bypass these.
    #ifdef __arm__
    asm volatile (
                  "mov r0, #31\n"
                  "mov r1, #0\n"
                  "mov r2, #0\n"
                  "mov r12, #26\n"
                  "svc #80\n"
                  );
    NSLog(@"Bypassed syscall() ASM");
    #endif
    #ifdef __arm64__
    asm volatile (
                  "mov x0, #26\n"
                  "mov x1, #31\n"
                  "mov x2, #0\n"
                  "mov x3, #0\n"
                  "mov x16, #0\n"
                  "svc #128\n"
                  );
    NSLog(@"Bypassed syscall() ASM64");
    #endif
    
    
    
    
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
