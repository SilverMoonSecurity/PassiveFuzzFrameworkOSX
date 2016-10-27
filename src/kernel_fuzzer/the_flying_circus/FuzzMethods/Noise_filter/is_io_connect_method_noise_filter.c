//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "noise_filter.h"
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "process.h"

//#include <IOkit/IOUserClient.h>


//FILTER_STATE gCurrentFilterState = UNKNOWN_STATE;


//New use

//////////////////2015-10-13-little version///////
/*
#if 0
detail_control_entry_t g_white_listing_detail_control[] =
{
    //Bypass unknown
    "*","*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    //Reported or collected yet:
    "*","*","AGPMClient",7312,
    "*","*", "nvDeviceTesla", 5,
    "*","*", "NV2DContextTesla", 17,
    "*","*","IONVSurfaceTesla",10,
    "*","*","nvTeslaSurfaceTesla",10,
    "*","*","nvTeslaSurfaceTesla",9,
    "*","*","IONVDVDContextTesla",14,
    "*","*","IONVGLContextTesla",11,
    "*","*","IOHDIX",2,
    
    //By experience:
    "profil","*","*",ANY_MATCH_INTEGER,
    "notify","*","*",ANY_MATCH_INTEGER,
    "watchdog","*","*",ANY_MATCH_INTEGER,
    "vmware","*","*",ANY_MATCH_INTEGER,
    
    "*","*","vmware",ANY_MATCH_INTEGER,
    
    "*","*","AppleOSXWatchdogClient",ANY_MATCH_INTEGER,
    "*","*","AppleSMCClient",ANY_MATCH_INTEGER,
    
    //Testing:
    "SystemUIServer","*","*",ANY_MATCH_INTEGER,
    "WindowServer","*","*",ANY_MATCH_INTEGER,
    
    "dock","*","*",ANY_MATCH_INTEGER,
    "*","*","doc",ANY_MATCH_INTEGER,
    "*","*", "Graphic", ANY_MATCH_INTEGER,
    "*","*","nvTeslaSurfaceTesla",ANY_MATCH_INTEGER,
    "*","*","NVDVDContextTesla",ANY_MATCH_INTEGER,
    "*","*","IONVSurfaceTesla",ANY_MATCH_INTEGER,
    "*","*","Tesla",ANY_MATCH_INTEGER,

};

///////////////////BlackListing
//New use
detail_control_entry_t g_black_listing_detail_control[] =
{
    //Checking:
    "*","*","HDIX",ANY_MATCH_INTEGER,
     //"*","*","surface",ANY_MATCH_INTEGER,
    //"*","*","io",ANY_MATCH_INTEGER,
    //"*","*","gra",ANY_MATCH_INTEGER,
    //"*","*","aud",ANY_MATCH_INTEGER,
    //"*","*","font",ANY_MATCH_INTEGER,
    //"*","*","text",ANY_MATCH_INTEGER,
    //Checking no call:
    "*","*","famil",ANY_MATCH_INTEGER,
     "*","*","net",ANY_MATCH_INTEGER,
};
#endif
*/

//In use Now!!!!
////////////////////////////////////2015-10-13 Full version/////////////
//2015-11-17
//Config for mac mini-old
/*
detail_control_entry_t g_white_listing_detail_control[] =
{
    "*",0,"*","*",ANY_MATCH_INTEGER,
    //Reported or collected yet:
    "*",PROCESS_UID_ANY_INTEGER,"*","AGPM",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","AGPMClient",7312,
    "*",PROCESS_UID_ANY_INTEGER,"*", "nvDeviceTesla", 5,//Reported2ZDI already-crash26
    "*",PROCESS_UID_ANY_INTEGER,"*", "NV2DContextTesla", 17,
    "*",PROCESS_UID_ANY_INTEGER,"*","IONVSurfaceTesla",10,
    "*",PROCESS_UID_ANY_INTEGER,"*","nvTeslaSurfaceTesla",10,
    "*",PROCESS_UID_ANY_INTEGER,"*","nvTeslaSurfaceTesla",9,
    "*",PROCESS_UID_ANY_INTEGER,"*","IONVDVDContextTesla",14,
    "*",PROCESS_UID_ANY_INTEGER,"*","IONVGLContextTesla",11,
    "*",PROCESS_UID_ANY_INTEGER,"*","IOHDIXHDDriveOutKernelUserClient",2,
    "kernel_task",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    //By experience:
    "profil",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "notify",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
     "watchdog",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"vmware",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,

    //"*",PROCESS_UID_ANY_INTEGER,"*","vmware",ANY_MATCH_INTEGER,

    "*",PROCESS_UID_ANY_INTEGER,"*","AppleOSXWatchdogClient",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","AppleSMCClient",ANY_MATCH_INTEGER,

    //Testing:
    "SystemUIServer",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "WindowServer",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,

    "dock",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","doc",ANY_MATCH_INTEGER,
    
    //2015-11-20
    "*",PROCESS_UID_ANY_INTEGER,"*","tesla",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","surf",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "Graphic", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","nvTeslaSurfaceTesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","NVDVDContextTesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","IONVSurfaceTesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Tesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "Tesla", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "nvDeviceTesla", ANY_MATCH_INTEGER, //Now
    
     //"*",PROCESS_UID_ANY_INTEGER,"*", "UserClient", ANY_MATCH_INTEGER,
     //"*",PROCESS_UID_ANY_INTEGER,"*", "Surf", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","apple",ANY_MATCH_INTEGER,
};

///////////////////BlackListing
//New use


detail_control_entry_t g_black_listing_detail_control[] =
{

    "*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //Checked:
    "safari",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "bash",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sh",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "python",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","audio",ANY_MATCH_INTEGER,
    "ping",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"replay",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"wire",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quick",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HDIX",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","frame",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","bolt",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","USB",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","file",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","store",ANY_MATCH_INTEGER,
    
    "*",PROCESS_UID_ANY_INTEGER,"*","blue",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","system",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","disk",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HW",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","stor",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","intel",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","intel",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","hd",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","PCI",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","SCSI",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","SMC",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","seri",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","FS",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","LPC",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","SMC",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","key",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","light",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","apple",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","cont",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","famil",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","lib",ANY_MATCH_INTEGER,
    "termi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "stor",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "apple",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "agent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "serv",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","acc",ANY_MATCH_INTEGER,
    "help",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "work",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "data",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quick",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "laun",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sys",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","us",ANY_MATCH_INTEGER,
    "d",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HDIX",ANY_MATCH_INTEGER,
    //Check possible ok:
    //"*",PROCESS_UID_ANY_INTEGER,"*","air",ANY_MATCH_INTEGER,//May cause black screen
    //"*",PROCESS_UID_ANY_INTEGER,"*","networking",ANY_MATCH_INTEGER,//Would hang via wifi
    //"*",PROCESS_UID_ANY_INTEGER,"*","80211",ANY_MATCH_INTEGER,//Would hang via wifi
    //"lib",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    
    //Check failed:
    //"*",PROCESS_UID_ANY_INTEGER,"*","net",ANY_MATCH_INTEGER,//Would hang via wifi
    //"webkit",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","device",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","root",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","HD",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","IO",ANY_MATCH_INTEGER,
    //"wifi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"disk",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"content",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"power",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,

    "excel",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "power",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "word",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //Game
    "dark",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "shark",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "bird",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "grim",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "race",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "wine",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quart",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "civi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "metro",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "anox",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "photo",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "plant",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "rac",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sim",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //Checking:
    //"*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,

    "ntfs",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"ntfs","*",ANY_MATCH_INTEGER,
    "scree",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //To Check:
    //"*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","surf",ANY_MATCH_INTEGER,//*Heavily called

    //"dump",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"agent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"apple",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"net",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"com",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"agent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,

    //"webkit",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"blued",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
     //"hidd",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"ptmd",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"sh",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER

    //"*",PROCESS_UID_ANY_INTEGER,"*","Family",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","surf",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
     //"*",PROCESS_UID_ANY_INTEGER,"*","Client",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","media", ANY_MATCH_INTEGER,
   //* "*",PROCESS_UID_ANY_INTEGER,"*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","IO",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Apple",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Client",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","USB",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","device",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","audio",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","intel",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","net",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","blue",ANY_MATCH_INTEGER

    //"*",PROCESS_UID_ANY_INTEGER,"*","nv",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Tesla", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","GL", ANY_MATCH_INTEGER

    //"*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","xxxxxxIO",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Apple",ANY_MATCH_INTEGER,
    
    
    
    "webkit",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "webcontent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "chrome",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //Call by chrom gpu
    "*",PROCESS_UID_ANY_INTEGER,"*","Graphics",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","Acceleration",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","Domain",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","AGPM",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IOSurface",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","ControlClient",ANY_MATCH_INTEGER,
    
    //Wifi control
    "networksetup",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "airport",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sh",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "python",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    "*",PROCESS_UID_ANY_INTEGER,"*","net",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","work",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","fami",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,

    
};
/**/

//*
//Config for mac pro
detail_control_entry_t g_white_listing_detail_control[] =
{
    // procName,uid,driverBundleName, driverClassName, selFunctionNO
    
    //"*",0,"*","*",ANY_MATCH_INTEGER,
#if 0
    //Reported or collected yet:
    //{"*",PROCESS_UID_ANY_INTEGER,"*","AGPMClient",7312},
    //{"*",PROCESS_UID_ANY_INTEGER,"*", "nvDeviceTesla", 5},
    //{"*",PROCESS_UID_ANY_INTEGER,"*", "NV2DContextTesla", 17},
    //{"*",PROCESS_UID_ANY_INTEGER,"*","IONVSurfaceTesla",10},
    //{"*",PROCESS_UID_ANY_INTEGER,"*","nvTeslaSurfaceTesla",10},
    //{"*",PROCESS_UID_ANY_INTEGER,"*","nvTeslaSurfaceTesla",9},
    //{"*",PROCESS_UID_ANY_INTEGER,"*","IONVDVDContextTesla",14},
    //{"*",PROCESS_UID_ANY_INTEGER,"*","IONVGLContextTesla",11},
    //{"*",PROCESS_UID_ANY_INTEGER,"*","IOHDIXHDDriveOutKernelUserClient",2},
    {"*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSharedUserClient",1},//crash-24
    {"*",PROCESS_UID_ANY_INTEGER,"*","AccelSurface",16},//crash-23
    {"*",PROCESS_UID_ANY_INTEGER,"*",OBJECT_CLASS_NAME_NO_FOUND,16},
    {"*",PROCESS_UID_ANY_INTEGER,"*","HD",2},//crash-21
    {"*",PROCESS_UID_ANY_INTEGER,"*","IX",2},//crash-21
    "*",PROCESS_UID_ANY_INTEGER,"*","AGPM",7312,//crash-11
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelGLContext",2,//crash-28
    //"*",PROCESS_UID_ANY_INTEGER,"*","Accel",2,//crash-28
    //"*",PROCESS_UID_ANY_INTEGER,"*","IG",2,//crash-28
    //"*",PROCESS_UID_ANY_INTEGER,"*","Con",2,//crash-28
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSharedUserClient",0,//crash-29
    "*",PROCESS_UID_ANY_INTEGER,"*","IOThunderboltFamilyUserClient",22,//crash-30
    "*",PROCESS_UID_ANY_INTEGER,"*","IOI2CInterfaceUserClient",2,//crash-31
     "*",PROCESS_UID_ANY_INTEGER,"*","IOAccelGLContext2",257,//crash-32, object class right/?
     "*",PROCESS_UID_ANY_INTEGER,"*","IOThunderboltFamilyUserClient",2,//crash-33
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelGLContext",257,//crash-34=crash-32
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSurface",9,//crash-35
    "*",PROCESS_UID_ANY_INTEGER,"*","IOThunderboltFamilyUserClient",2,//crash-33
    "*",PROCESS_UID_ANY_INTEGER,"*","IOHDIXHDDriveOutKernelUserClient",2,
    "diskimages-helpe",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IOUSBDeviceUserClientV2",4,//tocheck-32
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSharedUserClient",2,//tocheck-33
    //"*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSharedUserClient",ANY_MATCH_INTEGER,//tocheck-35-36
#endif
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSharedUserClient",0,//tocheck-43
    //By experience:
    //"profil",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"notify",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"watchdog",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"vmware",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*","PROCESS_UID_ANY_INTEGER,*","vmware",ANY_MATCH_INTEGER,
    
    //"*",PROCESS_UID_ANY_INTEGER,"*","AppleOSXWatchdogClient",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","AppleSMCClient",ANY_MATCH_INTEGER,
    
    //Testing:
    //"SystemUIServer",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"WindowServer",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    //"dock",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","doc",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "Graphic", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","nvTeslaSurfaceTesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","NVDVDContextTesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","IONVSurfaceTesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Tesla",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "Tesla", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "nvDeviceTesla", ANY_MATCH_INTEGER, //Now
    
    //"*",PROCESS_UID_ANY_INTEGER,"*", "UserClient", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "Surf", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","apple",ANY_MATCH_INTEGER,
    
    //"kernel_task","*","*",ANY_MATCH_INTEGER,//watchdog
    "*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,//Bypass touch
    "*",PROCESS_UID_ANY_INTEGER,"*","touch",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","pad",ANY_MATCH_INTEGER,

    //"*",PROCESS_UID_ANY_INTEGER,"*","IGAccelGLContext",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","AccelSurface",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","IG",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","Accel",ANY_MATCH_INTEGER,
    //"vm",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","vm",ANY_MATCH_INTEGER,
    "sandbox",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "dog",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //{"WindowServer",PROCESS_UID_ANY_INTEGER,"*","AccelSurface",16},//crash-23
    //"*",PROCESS_UID_ANY_INTEGER,"*","SMC",ANY_MATCH_INTEGER,
    //"windowserver",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
};

///////////////////BlackListing

detail_control_entry_t g_black_listing_detail_control[] =
{
//Ever test ok on mac pro
  
    //"*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "diskimages-helpe",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
#if 1
    "*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSurface",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelGLContext",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccel2DContext",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IOAccelDisplayPipeUserClient2",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelSharedUserClient",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelDevice",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IOAccelmemoryInfoUserClient",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelCLContext",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelCommandQueue",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IGAccelVideoContext",ANY_MATCH_INTEGER,
#if 1
    //Game
    "dark",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "shark",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "bird",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "grim",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "race",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "wine",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quart",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "civi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "metro",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "anox",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "photo",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "plant",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "rac",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sim",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //Checking:
    //"*",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","blue",ANY_MATCH_INTEGER,
    //"safari",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*", "Grap", ANY_MATCH_INTEGER,
    //"d",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","audio",ANY_MATCH_INTEGER,
    "ping",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"replay",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //"wire",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quick",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "ntfs",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","ntfs",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","acce",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","apple",ANY_MATCH_INTEGER,
#endif
    
    #if 1
    //Checked:
    //"*","*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    "safari",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "webkit",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    "bash",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sh",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "python",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","audio",ANY_MATCH_INTEGER,
    "ping",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "replay",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "wire",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quick",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HDIX",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","frame",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","bolt",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","USB",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","file",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","store",ANY_MATCH_INTEGER,
   
    "*",PROCESS_UID_ANY_INTEGER,"*","blue",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","system",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","disk",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HW",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","stor",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","intel",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","intel",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","hd",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","PCI",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","SCSI",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","SMC",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","seri",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","FS",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","LPC",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","SMC",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","key",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","light",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","apple",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","cont",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","famil",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","lib",ANY_MATCH_INTEGER,
    "termi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "stor",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "apple",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "agent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "serv",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","acc",ANY_MATCH_INTEGER,
    "help",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "work",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "data",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quick",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "laun",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sys",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","us",ANY_MATCH_INTEGER,
    "d",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HDIX",ANY_MATCH_INTEGER,
    //Check possible ok:
    "*",PROCESS_UID_ANY_INTEGER,"*","air",ANY_MATCH_INTEGER,//May cause black screen
    "*",PROCESS_UID_ANY_INTEGER,"*","networking",ANY_MATCH_INTEGER,//Would hang via wifi
    "*",PROCESS_UID_ANY_INTEGER,"*","80211",ANY_MATCH_INTEGER,//Would hang via wifi
    "lib",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    #endif 
    
    //Check failed:
    
    "*",PROCESS_UID_ANY_INTEGER,"*","net",ANY_MATCH_INTEGER,//Would hang via wifi
    "*",PROCESS_UID_ANY_INTEGER,"*","device",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","root",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HD",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","IO",ANY_MATCH_INTEGER,
    "wifi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "disk",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "content",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "power",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
      
    
    
    //Game
    
    "dark",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "shark",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "bird",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "grim",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "race",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "wine",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "quart",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "civi",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "metro",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "anox",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "photo",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "plant",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "rac",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sim",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "red",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "cs",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "earth",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "win",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    //Checking:
 
    "ntfs",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"ntfs","*",ANY_MATCH_INTEGER,
 
    //To Check:
    
    //"*",PROCESS_UID_ANY_INTEGER,"*","surf",ANY_MATCH_INTEGER,//*Heavily called
    "dump",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "agent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "apple",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "net",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "com",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "agent",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    "webkit",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "blued",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "hidd",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "ptmd",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    "sh",PROCESS_UID_ANY_INTEGER,"*","*",ANY_MATCH_INTEGER,
    
    "*",PROCESS_UID_ANY_INTEGER,"*","Family",ANY_MATCH_INTEGER,
    
    "*",PROCESS_UID_ANY_INTEGER,"*","media", ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","IO",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","Apple",ANY_MATCH_INTEGER,
    
    "*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","USB",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","device",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","HID",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","audio",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","intel",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","thunder",ANY_MATCH_INTEGER,
   "*",PROCESS_UID_ANY_INTEGER,"*","net",ANY_MATCH_INTEGER,
   "*",PROCESS_UID_ANY_INTEGER,"*","blue",ANY_MATCH_INTEGER,
    
    //"*",PROCESS_UID_ANY_INTEGER,"*","nv",ANY_MATCH_INTEGER,
   // "*",PROCESS_UID_ANY_INTEGER,"*","Tesla", ANY_MATCH_INTEGER,
    //"*",PROCESS_UID_ANY_INTEGER,"*","GL", ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","AGPM",ANY_MATCH_INTEGER,
    "*",PROCESS_UID_ANY_INTEGER,"*","apple",ANY_MATCH_INTEGER,
   // "*",PROCESS_UID_ANY_INTEGER,"*","UserClient",ANY_MATCH_INTEGER,
   "*",PROCESS_UID_ANY_INTEGER,"*","aud",ANY_MATCH_INTEGER,
    
#endif
};
/**/


/*
//Config for mac pro  of is_io_connect_async_method
//18:42 2015/12/1
detail_control_entry_t g_white_listing_detail_control[] =
{
#if 0
    //Reported or collected yet:
    //"*","*","AGPMClient",7312,
    //"*","*", "nvDeviceTesla", 5,
    //"*","*", "NV2DContextTesla", 17,
    //"*","*","IONVSurfaceTesla",10,
    //"*","*","nvTeslaSurfaceTesla",10,
    //"*","*","nvTeslaSurfaceTesla",9,
    //"*","*","IONVDVDContextTesla",14,
    //"*","*","IONVGLContextTesla",11,
    //"*","*","IOHDIXHDDriveOutKernelUserClient",2,
    "*","*","IGAccelSharedUserClient",1,//crash-24
    "*","*","AccelSurface",16,//crash-23
    "*","*",OBJECT_CLASS_NAME_NO_FOUND,16,
    "*","*","HD",2,//crash-21
    "*","*","IX",2,//crash-21
    "*","*","AGPM",7312,//crash-11
    "*","*","IGAccelGLContext",2,//crash-28
    //"*","*","Accel",2,//crash-28
    //"*","*","IG",2,//crash-28
    //"*","*","Con",2,//crash-28
    "*","*","IGAccelSharedUserClient",0,//crash-29
    "*","*","IOThunderboltFamilyUserClient",22,//crash-30
    "*","*","IOI2CInterfaceUserClient",2,//crash-31
     "*","*","IOAccelGLContext2",257,//crash-32, object class right/?
     "*","*","IOThunderboltFamilyUserClient",2,//crash-33
    "*","*","IGAccelGLContext",257,//crash-34=crash-32
    "*","*","IGAccelSurface",9,//crash-35
    "*","*","IOThunderboltFamilyUserClient",2,//crash-33
    "*","*","IOUSBInterfaceUserClient",23,//crash-36
    //By experience:
    "profil","*","*",ANY_MATCH_INTEGER,
    "notify","*","*",ANY_MATCH_INTEGER,
    "watchdog","*","*",ANY_MATCH_INTEGER,
    "vmware","*","*",ANY_MATCH_INTEGER,
    "*","*","vmware",ANY_MATCH_INTEGER,
    
    "*","*","AppleOSXWatchdogClient",ANY_MATCH_INTEGER,
    "*","*","AppleSMCClient",ANY_MATCH_INTEGER,
    
    //Testing:
    "SystemUIServer","*","*",ANY_MATCH_INTEGER,
    "WindowServer","*","*",ANY_MATCH_INTEGER,
    
    //"dock","*","*",ANY_MATCH_INTEGER,
    //"*","*","doc",ANY_MATCH_INTEGER,
    //"*","*", "Graphic", ANY_MATCH_INTEGER,
    //"*","*","nvTeslaSurfaceTesla",ANY_MATCH_INTEGER,
    //"*","*","NVDVDContextTesla",ANY_MATCH_INTEGER,
    //"*","*","IONVSurfaceTesla",ANY_MATCH_INTEGER,
    //"*","*","Tesla",ANY_MATCH_INTEGER,
    //"*","*", "Tesla", ANY_MATCH_INTEGER,
    //"*","*", "nvDeviceTesla", ANY_MATCH_INTEGER, //Now
    
    //"*","*", "UserClient", ANY_MATCH_INTEGER,
    //"*","*", "Surf", ANY_MATCH_INTEGER,
    //"*","*","apple",ANY_MATCH_INTEGER,
    
    "kernel_task","*","*",ANY_MATCH_INTEGER,//watchdog
    "*","*","HID",ANY_MATCH_INTEGER,//Bypass touch
    "*","*","touch",ANY_MATCH_INTEGER,
    "*","*","pad",ANY_MATCH_INTEGER,

    "*","*","IGAccelGLContext",ANY_MATCH_INTEGER,
    //"*","*","AccelSurface",ANY_MATCH_INTEGER,
    //"*","*","IG",ANY_MATCH_INTEGER,
    //"*","*","Accel",ANY_MATCH_INTEGER,
    "vm","*","*",ANY_MATCH_INTEGER,
#endif
    "*","*","vm",ANY_MATCH_INTEGER,
    //"sandbox","*","*",ANY_MATCH_INTEGER,
    //"*","*","SMC",ANY_MATCH_INTEGER,
   
};

///////////////////BlackListing

static detail_control_entry_t g_black_listing_detail_control[] =
{
    
#if 0
//Ever test ok on mac pro
    //Checked:
    //"*","*","*",ANY_MATCH_INTEGER,
    "*","*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    "safari","*","*",ANY_MATCH_INTEGER,
    "webkit","*","*",ANY_MATCH_INTEGER,
    
    "bash","*","*",ANY_MATCH_INTEGER,
    "sh","*","*",ANY_MATCH_INTEGER,
    "python","*","*",ANY_MATCH_INTEGER,
    "*","*","audio",ANY_MATCH_INTEGER,
    "ping","*","*",ANY_MATCH_INTEGER,
    "replay","*","*",ANY_MATCH_INTEGER,
    "wire","*","*",ANY_MATCH_INTEGER,
    "quick","*","*",ANY_MATCH_INTEGER,
    "*","*","HDIX",ANY_MATCH_INTEGER,
    "*","*","frame",ANY_MATCH_INTEGER,
    "*","*","HID",ANY_MATCH_INTEGER,
    "*","*","thunder",ANY_MATCH_INTEGER,
    "*","*","bolt",ANY_MATCH_INTEGER,
    "*","*","USB",ANY_MATCH_INTEGER,
    "*","*","file",ANY_MATCH_INTEGER,
    "*","*","store",ANY_MATCH_INTEGER,
   
    "*","*","blue",ANY_MATCH_INTEGER,
    "*","*","system",ANY_MATCH_INTEGER,
    "*","*","disk",ANY_MATCH_INTEGER,
    "*","*","HW",ANY_MATCH_INTEGER,
    "*","*","stor",ANY_MATCH_INTEGER,
    "*","*","intel",ANY_MATCH_INTEGER,
    "*","*","intel",ANY_MATCH_INTEGER,
    "*","*","hd",ANY_MATCH_INTEGER,
    "*","*","PCI",ANY_MATCH_INTEGER,
    "*","*","SCSI",ANY_MATCH_INTEGER,
    "*","*","SMC",ANY_MATCH_INTEGER,
    "*","*","seri",ANY_MATCH_INTEGER,
    "*","*","FS",ANY_MATCH_INTEGER,
    "*","*","LPC",ANY_MATCH_INTEGER,
    "*","*","SMC",ANY_MATCH_INTEGER,
    "*","*","thunder",ANY_MATCH_INTEGER,
    "*","*","key",ANY_MATCH_INTEGER,
    "*","*","light",ANY_MATCH_INTEGER,
    "*","*","apple",ANY_MATCH_INTEGER,
    "*","*","cont",ANY_MATCH_INTEGER,
    "*","*","famil",ANY_MATCH_INTEGER,
    "*","*","lib",ANY_MATCH_INTEGER,
    "termi","*","*",ANY_MATCH_INTEGER,
    "stor","*","*",ANY_MATCH_INTEGER,
    "apple","*","*",ANY_MATCH_INTEGER,
    "agent","*","*",ANY_MATCH_INTEGER,
    "serv","*","*",ANY_MATCH_INTEGER,
    "*","*","acc",ANY_MATCH_INTEGER,
    "help","*","*",ANY_MATCH_INTEGER,
    "work","*","*",ANY_MATCH_INTEGER,
    "data","*","*",ANY_MATCH_INTEGER,
    "quick","*","*",ANY_MATCH_INTEGER,
    "laun","*","*",ANY_MATCH_INTEGER,
    "sys","*","*",ANY_MATCH_INTEGER,
    "*","*","us",ANY_MATCH_INTEGER,
    "d","*","*",ANY_MATCH_INTEGER,
    "*","*","HDIX",ANY_MATCH_INTEGER,
    //Check possible ok:
    "*","*","air",ANY_MATCH_INTEGER,//May cause black screen
    "*","*","networking",ANY_MATCH_INTEGER,//Would hang via wifi
    "*","*","80211",ANY_MATCH_INTEGER,//Would hang via wifi
    "lib","*","*",ANY_MATCH_INTEGER,

    
    //Check failed:
    
    //"*","*","net",ANY_MATCH_INTEGER,//Would hang via wifi
    //"*","*","device",ANY_MATCH_INTEGER,
    //"*","*","root",ANY_MATCH_INTEGER,
    //"*","*","HD",ANY_MATCH_INTEGER,
    //"*","*","IO",ANY_MATCH_INTEGER,
    //"wifi","*","*",ANY_MATCH_INTEGER,
    //"disk","*","*",ANY_MATCH_INTEGER,
    //"content","*","*",ANY_MATCH_INTEGER,
    //"power","*","*",ANY_MATCH_INTEGER,
      
    //Application
    "chrome","*","*",ANY_MATCH_INTEGER,
    
    //Game
    "dark","*","*",ANY_MATCH_INTEGER,
    "shark","*","*",ANY_MATCH_INTEGER,
    "bird","*","*",ANY_MATCH_INTEGER,
    "grim","*","*",ANY_MATCH_INTEGER,
    "race","*","*",ANY_MATCH_INTEGER,
    "wine","*","*",ANY_MATCH_INTEGER,
    "quart","*","*",ANY_MATCH_INTEGER,
    "civi","*","*",ANY_MATCH_INTEGER,
    "metro","*","*",ANY_MATCH_INTEGER,
    "anox","*","*",ANY_MATCH_INTEGER,
    "photo","*","*",ANY_MATCH_INTEGER,
    "plant","*","*",ANY_MATCH_INTEGER,
    "rac","*","*",ANY_MATCH_INTEGER,
    "sim","*","*",ANY_MATCH_INTEGER,
    "red","*","*",ANY_MATCH_INTEGER,
    "cs","*","*",ANY_MATCH_INTEGER,
    "earth","*","*",ANY_MATCH_INTEGER,
    "win","*","*",ANY_MATCH_INTEGER,
    //Checking:
 
    "ntfs","*","*",ANY_MATCH_INTEGER,
    "*","ntfs","*",ANY_MATCH_INTEGER,
 
    //To Check:
    
    //"*","*","surf",ANY_MATCH_INTEGER,//*Heavily called
    //"dump","*","*",ANY_MATCH_INTEGER,
    //"agent","*","*",ANY_MATCH_INTEGER,
    //"apple","*","*",ANY_MATCH_INTEGER,
    //"net","*","*",ANY_MATCH_INTEGER,
    //"com","*","*",ANY_MATCH_INTEGER,
    //"agent","*","*",ANY_MATCH_INTEGER,
    
    //"webkit","*","*",ANY_MATCH_INTEGER,
    //"blued","*","*",ANY_MATCH_INTEGER,
    //"hidd","*","*",ANY_MATCH_INTEGER,
    //"ptmd","*","*",ANY_MATCH_INTEGER,
    //"sh","*","*",ANY_MATCH_INTEGER,
    
    //"*","*","Family",ANY_MATCH_INTEGER,
    //"*","*","Client",ANY_MATCH_INTEGER,
    //"*","*","media", ANY_MATCH_INTEGER,
    //"*","*",OBJECT_CLASS_NAME_NO_FOUND,ANY_MATCH_INTEGER,
    //"*","*","IO",ANY_MATCH_INTEGER,
    //"*","*","Apple",ANY_MATCH_INTEGER,
    //"*","*","Client",ANY_MATCH_INTEGER,
    //"*","*","HID",ANY_MATCH_INTEGER,
    //"*","*","USB",ANY_MATCH_INTEGER,
    //"*","*","device",ANY_MATCH_INTEGER,
    //"*","*","HID",ANY_MATCH_INTEGER,
    //"*","*","audio",ANY_MATCH_INTEGER,
    //"*","*","intel",ANY_MATCH_INTEGER,
    //"*","*","thunder",ANY_MATCH_INTEGER,
    //"*","*","net",ANY_MATCH_INTEGER,
   //"*","*","blue",ANY_MATCH_INTEGER,
    
    //"*","*","nv",ANY_MATCH_INTEGER,
   // "*","*","Tesla", ANY_MATCH_INTEGER,
    //"*","*","GL", ANY_MATCH_INTEGER,
    "*","*","AGPM",ANY_MATCH_INTEGER,
    "*","*","apple",ANY_MATCH_INTEGER,
   // "*","*","UserClient",ANY_MATCH_INTEGER,
   //"*","*","aud",ANY_MATCH_INTEGER,
#endif
 
    

 "webkit","*","*",ANY_MATCH_INTEGER,
#if 0
    "webcontent","*","*",ANY_MATCH_INTEGER,
 "chrome","*","*",ANY_MATCH_INTEGER,
 //Call by chrom gpu
 "*","*","Graphics",ANY_MATCH_INTEGER,
 "*","*","Acceleration",ANY_MATCH_INTEGER,
 "*","*","Domain",ANY_MATCH_INTEGER,
 //"*","*","AGPM",ANY_MATCH_INTEGER,
 "*","*","IOSurface",ANY_MATCH_INTEGER,
 "*","*","ControlClient",ANY_MATCH_INTEGER,
 
 //Wifi control
 "networksetup","*","*",ANY_MATCH_INTEGER,
 "airport","*","*",ANY_MATCH_INTEGER,
 "sh","*","*",ANY_MATCH_INTEGER,
 "python","*","*",ANY_MATCH_INTEGER,
 
 "*","*","net",ANY_MATCH_INTEGER,
 "*","*","work",ANY_MATCH_INTEGER,
 "*","*","fami",ANY_MATCH_INTEGER,
 "*","*","*",ANY_MATCH_INTEGER,
#endif
};
/**/



/*
detail_control_entry_t g_white_listing_detail_control[] =
{
 
    "*","*","IGAccelSharedUserClient",1//crash-24
   
};

///////////////////BlackListing

detail_control_entry_t g_black_listing_detail_control[] =
{

    "webkit","*","*",ANY_MATCH_INTEGER,
    "webcontent","*","*",ANY_MATCH_INTEGER,
    "chrome","*","*",ANY_MATCH_INTEGER,
    //Call by chrom gpu
    "*","*","Graphics",ANY_MATCH_INTEGER,
    "*","*","Acceleration",ANY_MATCH_INTEGER,
    "*","*","Domain",ANY_MATCH_INTEGER,
    "*","*","AGPM",ANY_MATCH_INTEGER,
    "*","*","IOSurface",ANY_MATCH_INTEGER,
    "*","*","ControlClient",ANY_MATCH_INTEGER,
};
/**/


////////////////////////////////////////////////////////////////////////////////////////
//White Listing
boolean_t should_bypass_within_is_io_connect_method(fuzz_sample_info_t * pEntry)
{
    boolean_t bBypass = false;
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bBypass = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_is_io_connect_method, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
 
    bMatched = match_detail_control_entry_list_for_io_connect_method(WHITE_LISTING_STATE, pEntry,
        g_white_listing_detail_control,
            sizeof(g_white_listing_detail_control)/sizeof(detail_control_entry_t));
    
  
_EXIT: 
    if (bMatched)
    {
        //__asm__ volatile ("int3");
        //moony_modify//printf("[DEBUG]  allowed for [%s], PID[%x], className=[%s], object=0x%llx\r\n",path,pid,szClassName,object);
        bBypass = true;
    }
    return bBypass;
}


///////////////////////////////////////////////////
//Black listing
boolean_t should_fuzz_within_is_io_connect_method(fuzz_sample_info_t * pEntry)
{
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bMatched = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_is_io_connect_method, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
    
    bMatched = match_detail_control_entry_list_for_io_connect_method(BLACK_LISTING_STATE, pEntry,
                                               g_black_listing_detail_control,
                                               sizeof(g_black_listing_detail_control)/sizeof(detail_control_entry_t));
    
    if (bMatched)
    {
        //moony_modify//printf("[DEBUG] should_bypass_within_is_io_connect_method, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
_EXIT:

    return bMatched;
}





boolean_t match_detail_control_entry_list_for_io_connect_method(FILTER_STATE state, fuzz_sample_info_t * pSampleInfo, pdetail_control_entry_t listing_head, unsigned int uLen)
{
    boolean_t bMatched = false;
    if ( !listing_head || uLen ==0)
    {
        bMatched = true;
        goto _EXIT;
    }
    if (!pSampleInfo)
    {
        goto _EXIT;
    }
    for(int i = 0; i<uLen;i++)
    {
        bMatched = match_detail_control_handler_for_io_connect_method(state, pSampleInfo, &(listing_head[i]));
        if (bMatched)
        {
            break;
        }
    }
    
_EXIT:
    
    return bMatched;
}




boolean_t  match_detail_control_handler_for_io_connect_method(FILTER_STATE state, fuzz_sample_info_t *pSampleInfo, pdetail_control_entry_t pCtlEntry)
{
    boolean_t bMatched = false;
    boolean_t bMatchedProc = false;
    boolean_t bMatchedSelector = false;
    boolean_t bMatchedClass = false;
    boolean_t bMatchedUid = false;
    uint64_t uid = 0;
    if (!pSampleInfo)
    {
        goto _EXIT;
    }
    if (!pCtlEntry)
    {
        bMatched = true;
        goto _EXIT;
    }
    
    //Cmp uid
    uid = kauth_getuid();
    bMatchedUid = match_int(uid, pCtlEntry->uid);
    if (!bMatchedUid)
    {
        goto _DONE;
    }

    //Cmp proc name
    bMatchedProc = match_str(pSampleInfo->env.szProcName, pCtlEntry->procName);
    if (!bMatchedProc)
    {
        //bMatched = false;
        goto _DONE;
    }
    
    //Cmp class Name
    
    bMatchedClass = match_str(pSampleInfo->env.szClassName, pCtlEntry->driverClassName);
    if (!bMatchedClass)
    {
        //bMatched = false;
        goto _DONE;
    }
    
    //Get Selector
    if (match_int(pSampleInfo->original.entry.selector,pCtlEntry->selFunctionNO))
    {
        bMatchedSelector = true;
        goto _DONE;
    }
    
_DONE:
    
    
    
_EXIT:
    if (bMatchedProc && bMatchedClass && bMatchedSelector && bMatchedUid )
    {
        
        //__asm__ volatile ("int3");
        //moony_modify//printf("[DEBUG]  allowed for [%s], PID[%x], className=[%s], object=0x%llx\r\n",path,pid,szClassName,object);
        bMatched = true;
        switch (state) {
            case WHITE_LISTING_STATE:
                pSampleInfo->noise.white.entry.bMatched = true;
                pSampleInfo->noise.white.entry.matchedRule = *pCtlEntry;
                break;
            case BLACK_LISTING_STATE:
                pSampleInfo->noise.black.entry.bMatched = true;
                pSampleInfo->noise.black.entry.matchedRule = *pCtlEntry;
                break;
            default:
                break;
        }
        
    }
    return bMatched;
}

