#pragma once

// Include ntddk.h (driver) or windows.h + winioctl.h (client) before this file.
// Both sides compile the same ABI: no pointers, size_t, BOOLEAN or native handles.
#define ND_DEVICE_TYPE 0x8001UL
#define ND_DEVICE_NT L"\\Device\\NetworkDriver"
#define ND_DEVICE_DOS L"\\DosDevices\\NetworkDriver"
#define ND_DEVICE_USER L"\\\\.\\NetworkDriver"
#define ND_VERSION 1UL
#define ND_EVENT_CAPACITY 128UL
#define ND_BATCH_CAPACITY 32UL

// METHOD_BUFFERED gives us a captured SystemBuffer, never a raw user pointer.
// Handle access is checked by the I/O manager before dispatching these requests.
#define IOCTL_ND_SET_RULE CTL_CODE(ND_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_ND_GET_STATS CTL_CODE(ND_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_ND_READ_EVENTS CTL_CODE(ND_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#define ND_DIRECTION_ANY 0UL
#define ND_DIRECTION_OUTBOUND 1UL
#define ND_DIRECTION_INBOUND 2UL
#define ND_PROTOCOL_ANY 0UL
#define ND_PROTOCOL_TCP 6UL
#define ND_PROTOCOL_UDP 17UL
#define ND_ACTION_CONTINUE 0UL
#define ND_ACTION_BLOCK 1UL
#define ND_ACTION_NO_RIGHT 2UL

// IPv4 addresses are numeric host-order values: 127.0.0.1 is 0x7F000001.
// ServicePort means remote port outbound, local port inbound. Zero = wildcard.
// All nonzero conditions are ANDed. Enabled=0 means observe without blocking.
// An enabled rule must specify an address or port, preventing an accidental block-all.
typedef struct _ND_RULE {
	ULONG Version;
	ULONG Size;
	ULONG Enabled;
	ULONG Direction;
	ULONG Protocol;
	ULONG RemoteAddress;
	ULONG ServicePort;
	ULONG Reserved;
} ND_RULE;

typedef struct _ND_ENDPOINT {
	ULONG Direction;
	ULONG Protocol;
	ULONG LocalAddress;
	ULONG RemoteAddress;
	ULONG LocalPort;
	ULONG RemotePort;
} ND_ENDPOINT;

// Events describe ALE authorization callbacks, NOT individual packets.
// Timestamp is UTC system time in 100-ns intervals since January 1, 1601.
typedef struct _ND_EVENT {
	ULONGLONG Sequence;
	ULONGLONG Timestamp;
	ULONGLONG ProcessId;
	ND_ENDPOINT Endpoint;
	ULONG Action;
	ULONG Reserved;
} ND_EVENT;

typedef struct _ND_STATS {
	ULONG Version;
	ULONG Size;
	ND_RULE Rule;
	ULONGLONG Observed;
	ULONGLONG Blocked;
	ULONGLONG NoActionRight;
	ULONGLONG Overwritten;
	ULONG Queued;
	ULONG Capacity;
} ND_STATS;

typedef struct _ND_EVENT_BATCH {
	ULONG Version;
	ULONG Size;
	ULONG Count;
	ULONG Reserved;
	ND_EVENT Events[ND_BATCH_CAPACITY];
} ND_EVENT_BATCH;

// Detect ABI drift at compile time in both x64 and ARM64 builds.
C_ASSERT(sizeof(ND_RULE) == 32);
C_ASSERT(sizeof(ND_ENDPOINT) == 24);
C_ASSERT(sizeof(ND_EVENT) == 56);
C_ASSERT(sizeof(ND_STATS) == 80);
C_ASSERT(sizeof(ND_EVENT_BATCH) == 1808);
