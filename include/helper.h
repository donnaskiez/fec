#ifndef HELPER_H
#define HELPER_H

#include <intrin.h>
#include <nmmintrin.h>
#include <ntstatus.h>
#include <stdio.h>

#define STATIC static

typedef UINT32 STATUS;

#define STATUS_SUCCESS (UINT32)0
#define STATUS_ERROR   (UINT32)1

#define SUCCESS(x) ((x) == STATUS_SUCCESS)

#define CLFLUSH_LINE_SIZE_BIT 8

#define ALIGN32(x)         (((x) + 3) & ~3)
#define COUNT_BITS(x)      (sizeof(x) * 8)
#define IS_SET(value, bit) ((value) & (1ULL << (bit)))

#endif