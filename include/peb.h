enum COMMON {
    NULL = 0x00,
    FALSE = 0x00,
    TRUE  = 0x01,
    INVALID_SOCKET = 0xffffffff,
};

typedef void* VOID;

typedef struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    VOID* Mutant;                                                           //0x4
    VOID* ImageBaseAddress;                                                 //0x8
    struct _PEB_LDR_DATA* Ldr;                                              //0xc
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
    VOID* SubSystemData;                                                    //0x14
    VOID* ProcessHeap;                                                      //0x18
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x20
    VOID* IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob:1;                                           //0x28
            ULONG ProcessInitializing:1;                                    //0x28
            ULONG ProcessUsingVEH:1;                                        //0x28
            ULONG ProcessUsingVCH:1;                                        //0x28
            ULONG ProcessUsingFTH:1;                                        //0x28
            ULONG ProcessPreviouslyThrottled:1;                             //0x28
            ULONG ProcessCurrentlyThrottled:1;                              //0x28
            ULONG ProcessImagesHotPatched:1;                                //0x28
            ULONG ReservedBits0:24;                                         //0x28
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x2c
        VOID* UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved;                                                   //0x30
    union _SLIST_HEADER* volatile AtlThunkSListPtr32;                       //0x34
    VOID* ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    VOID* TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    VOID* ReadOnlySharedMemoryBase;                                         //0x4c
    VOID* SharedData;                                                       //0x50
    VOID** ReadOnlyStaticServerData;                                        //0x54
    VOID* AnsiCodePageData;                                                 //0x58
    VOID* OemCodePageData;                                                  //0x5c
    VOID* UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    VOID** ProcessHeaps;                                                    //0x90
    VOID* GdiSharedHandleTable;                                             //0x94
    VOID* ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    VOID (*PostProcessInitRoutine)();                                       //0x14c
    VOID* TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    VOID* pShimData;                                                        //0x1e8
    VOID* AppCompatInfo;                                                    //0x1ec
    struct _UNICODE_STRING CSDVersion;                                      //0x1f0
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
    ULONG MinimumStackCommit;                                               //0x208
    VOID* SparePointers[4];                                                 //0x20c
    ULONG SpareUlongs[5];                                                   //0x21c
    VOID* WerRegistrationData;                                              //0x230
    VOID* WerShipAssertPtr;                                                 //0x234
    VOID* pUnused;                                                          //0x238
    VOID* pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x240
            ULONG CritSecTracingEnabled:1;                                  //0x240
            ULONG LibLoaderTracingEnabled:1;                                //0x240
            ULONG SpareTracingBits:29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    struct _LIST_ENTRY TppWorkerpList;                                      //0x254
    VOID* WaitOnAddressHashTable[128];                                      //0x25c
    VOID* TelemetryCoverageHeader;                                          //0x45c
    ULONG CloudFileFlags;                                                   //0x460
    ULONG CloudFileDiagFlags;                                               //0x464
    CHAR PlaceholderCompatibilityMode;                                      //0x468
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x470
    union
    {
        ULONG LeapSecondFlags;                                              //0x474
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x474
            ULONG Reserved:31;                                              //0x474
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x478
} PEB, *PPEB; 

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
    VOID* EntryInProgress;                                                  //0x24
    UCHAR ShutdownInProgress;                                               //0x28
    VOID* ShutdownThreadId;                                                 //0x2c
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;                                              //0x0
    struct _LIST_ENTRY* Blink;                                              //0x4
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
    VOID* DllBase;                                                          //0x18
    VOID* EntryPoint;                                                       //0x1c
    ULONG SizeOfImage;                                                      //0x20
    struct _UNICODE_STRING FullDllName;                                     //0x24
    struct _UNICODE_STRING BaseDllName;                                     //0x2c
    union
    {
        UCHAR FlagGroup[4];                                                 //0x34
        ULONG Flags;                                                        //0x34
        struct
        {
            ULONG PackagedBinary:1;                                         //0x34
            ULONG MarkedForRemoval:1;                                       //0x34
            ULONG ImageDll:1;                                               //0x34
            ULONG LoadNotificationsSent:1;                                  //0x34
            ULONG TelemetryEntryProcessed:1;                                //0x34
            ULONG ProcessStaticImport:1;                                    //0x34
            ULONG InLegacyLists:1;                                          //0x34
            ULONG InIndexes:1;                                              //0x34
            ULONG ShimDll:1;                                                //0x34
            ULONG InExceptionTable:1;                                       //0x34
            ULONG ReservedFlags1:2;                                         //0x34
            ULONG LoadInProgress:1;                                         //0x34
            ULONG LoadConfigProcessed:1;                                    //0x34
            ULONG EntryProcessed:1;                                         //0x34
            ULONG ProtectDelayLoad:1;                                       //0x34
            ULONG ReservedFlags3:2;                                         //0x34
            ULONG DontCallForThreads:1;                                     //0x34
            ULONG ProcessAttachCalled:1;                                    //0x34
            ULONG ProcessAttachFailed:1;                                    //0x34
            ULONG CorDeferredValidate:1;                                    //0x34
            ULONG CorImage:1;                                               //0x34
            ULONG DontRelocate:1;                                           //0x34
            ULONG CorILOnly:1;                                              //0x34
            ULONG ChpeImage:1;                                              //0x34
            ULONG ReservedFlags5:2;                                         //0x34
            ULONG Redirected:1;                                             //0x34
            ULONG ReservedFlags6:2;                                         //0x34
            ULONG CompatDatabaseProcessed:1;                                //0x34
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x38
    USHORT TlsIndex;                                                        //0x3a
    struct _LIST_ENTRY HashLinks;                                           //0x3c
    ULONG TimeDateStamp;                                                    //0x44
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x48
    VOID* Lock;                                                             //0x4c
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x50
    struct _LIST_ENTRY NodeModuleLink;                                      //0x54
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0x5c
    VOID* ParentDllBase;                                                    //0x60
    VOID* SwitchBackContext;                                                //0x64
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0x68
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0x74
    ULONG OriginalBase;                                                     //0x80
    union _LARGE_INTEGER LoadTime;                                          //0x88
    ULONG BaseNameHashValue;                                                //0x90
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x94
    ULONG ImplicitPathOptions;                                              //0x98
    ULONG ReferenceCount;                                                   //0x9c
    ULONG DependentLoadFlags;                                               //0xa0
    UCHAR SigningLevel;                                                     //0xa4
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
