1. What is it
  This framework is for fuzzing OSX kernel vulnerability based on passive inline hook mechanism in kernel mode.
Basically, it is a typical kernel driver which inline-hooked import API related to IOKit framework and kernel service.
You could collect kernel dump and reproduce the vulnerability if kernel crash happens.
You can follow my twitter: @Flyic (of moony li)to more info in detail.
The source code is to be released after our presentation "Active fuzzing as complementary for passive fuzzing" on PacSec 2016 in Tokyo(10.26/10.27)
https://pacsec.jp/speakers.html
 
  The passive fuzzing framework is based on “the_flying_circus” rootkit for OSX by fG!
 * A Mountain Lion rootkit for Phrack #69!
 * Copyright (c) fG!, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
  Special thanks to fG!

2. Requirement for running
  In principle, the passive fuzzing framework could support popular OSX version for Mac Pro,Air. 
  As our experience, there kernel revision from 10.11 to 10.11.6 cause little or non interference to passive fuzzing. 
  The framework has been tested on 10.11.6 MacPro with KDK_10.11.6_15G31.kdk.

3. How to use
3.1 Quick Start
	If you want to try the passive fuzz just for fun, please quick try like this:
	a. Load driver for  quick passive fuzz
		sh-3.2# chown -R root:wheel ./quick-pasive_kernel_fuzz.kext
		sh-3.2# kextutil ./quick-pasive_kernel_fuzz.kext
	b. quick-pasive_kernel_fuzz would appear in kernel module
		sh-3.2# kextstat
		You would see the driver appears in the kernel module list. However, 
3.2 Full Start
	a. Prepare KDK and nvram 
		I. Download KDK_10.11.6_15G31.kdk and install on your Mac machine
		II. Copy kernel.development to system folder and synchronise kernel cache
			sh-3.2# cp -fr /Library/Developer/KDKs/KDK_10.11.6_15G31.kdk/System/Library/Kernels/kernel.development* /System/Library/Kernels/
			sh-3.2# kextcache -invalid /
			sh-3.2# reboot
		III. Set up boot-args
			sh-3.2# nvram boot-args="debug=0x566 kdp_match_name=firewire fwkdp=0x8000 pmuflags=1 kext-dev-mode=1  -v"
			sh-3.2# reboot

	b. Load driver for passive fuzz
		sh-3.2# chown -R root:wheel ./pasive_kernel_fuzz.kext
		sh-3.2# kextutil ./pasive_kernel_fuzz.kext

	c. Proberbly your Mac Machine would kernel crash 