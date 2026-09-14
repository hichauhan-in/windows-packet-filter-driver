#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string.h>
#include "../Shared/NetworkRule.h"

static volatile LONG g_Stop;

static void NdUsage(void)
{
	puts("NetworkCtl - IPv4 TCP/UDP connection filtering lab (run elevated)\n"
		 "  NetworkCtl monitor\n"
		 "  NetworkCtl block <in|out|any> <tcp|udp|any> <remote-ipv4|any> <service-port|any>\n"
		 "  NetworkCtl stats\n"
		 "  NetworkCtl events\n"
		 "  NetworkCtl watch\n\n"
		 "Example: NetworkCtl block out tcp 127.0.0.1 8080\n"
		 "Service port = remote port outbound, local port inbound. Conditions are ANDed.\n"
		 "Events are connection authorizations, not packets. Ctrl+C stops watching;\n"
		 "it does NOT clear a block rule. Use 'monitor' to clear it.");
}

static int NdError(const char* Operation)
{
	DWORD error = GetLastError();
	char* message = NULL;

	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPSTR)&message, 0, NULL);
	fprintf(stderr, "%s failed (%lu): %s\n", Operation, error,
		message != NULL ? message : "No system message available.");
	if (message != NULL) {
		LocalFree(message);
	}
	return 1;
}

static int NdParseRule(char** Arguments, ND_RULE* Rule)
{
	IN_ADDR address;
	const char* digit;
	ULONG port = 0;

	Rule->Enabled = 1;
	if (strcmp(Arguments[0], "in") == 0) {
		Rule->Direction = ND_DIRECTION_INBOUND;
	} else if (strcmp(Arguments[0], "out") == 0) {
		Rule->Direction = ND_DIRECTION_OUTBOUND;
	} else if (strcmp(Arguments[0], "any") != 0) {
		return 0;
	}

	if (strcmp(Arguments[1], "tcp") == 0) {
		Rule->Protocol = ND_PROTOCOL_TCP;
	} else if (strcmp(Arguments[1], "udp") == 0) {
		Rule->Protocol = ND_PROTOCOL_UDP;
	} else if (strcmp(Arguments[1], "any") != 0) {
		return 0;
	}

	if (strcmp(Arguments[2], "any") != 0) {
		if (InetPtonA(AF_INET, Arguments[2], &address) != 1) {
			return 0;
		}
		Rule->RemoteAddress = ntohl(address.S_un.S_addr);
		// The ABI reserves zero as wildcard; require 'any' to express that.
		if (Rule->RemoteAddress == 0) {
			return 0;
		}
	}

	if (strcmp(Arguments[3], "any") != 0) {
		if (Arguments[3][0] == '\0') {
			return 0;
		}
		for (digit = Arguments[3]; *digit != '\0'; ++digit) {
			if (*digit < '0' || *digit > '9') {
				return 0;
			}
			port = port * 10 + (ULONG)(*digit - '0');
			if (port > 65535) {
				return 0;
			}
		}
		if (port == 0) {
			return 0;
		}
		Rule->ServicePort = port;
	}
	return NdRuleValid(Rule);
}

static const char* NdDirection(ULONG Direction)
{
	return Direction == ND_DIRECTION_OUTBOUND ? "out" :
		Direction == ND_DIRECTION_INBOUND ? "in" : "any";
}

static const char* NdProtocol(ULONG Protocol)
{
	return Protocol == ND_PROTOCOL_TCP ? "tcp" : Protocol == ND_PROTOCOL_UDP ? "udp" : "any";
}

static void NdPrintAddress(ULONG Address)
{
	printf("%lu.%lu.%lu.%lu", (Address >> 24) & 255, (Address >> 16) & 255,
		(Address >> 8) & 255, Address & 255);
}

static int NdPrintStats(HANDLE Device)
{
	ND_STATS stats = { 0 };
	DWORD returned = 0;

	if (!DeviceIoControl(Device, IOCTL_ND_GET_STATS, NULL, 0, &stats, sizeof(stats), &returned, NULL)) {
		return NdError("GET_STATS");
	}
	if (returned != sizeof(stats) || stats.Version != ND_VERSION || stats.Size != sizeof(stats)) {
		fputs("Driver/client ABI mismatch. Rebuild and deploy matching binaries.\n", stderr);
		return 1;
	}
	printf("Mode: %s\nRule: %s %s remote=", stats.Rule.Enabled ? "block" : "monitor-only",
		NdDirection(stats.Rule.Direction), NdProtocol(stats.Rule.Protocol));
	if (stats.Rule.RemoteAddress == 0) {
		printf("any");
	} else {
		NdPrintAddress(stats.Rule.RemoteAddress);
	}
	printf(" service-port=%lu (0=any)\n", stats.Rule.ServicePort);
	printf("Observed=%llu Blocked=%llu NoActionRight=%llu Overwritten=%llu Queued=%lu/%lu\n",
		stats.Observed, stats.Blocked, stats.NoActionRight, stats.Overwritten, stats.Queued, stats.Capacity);
	puts("CONTINUE does not mean permitted by the final firewall policy.");
	return 0;
}

static int NdReadEvents(HANDLE Device, ULONG* Count)
{
	ND_EVENT_BATCH batch = { 0 };
	DWORD returned = 0;
	ULONG index;

	if (!DeviceIoControl(Device, IOCTL_ND_READ_EVENTS, NULL, 0, &batch, sizeof(batch), &returned, NULL)) {
		return NdError("READ_EVENTS");
	}
	if (returned != sizeof(batch) || batch.Version != ND_VERSION ||
		batch.Size != sizeof(batch) || batch.Count > ND_BATCH_CAPACITY) {
		fputs("Invalid event response or driver/client ABI mismatch.\n", stderr);
		return 1;
	}
	*Count = batch.Count;
	for (index = 0; index < batch.Count; ++index) {
		const ND_EVENT* event = &batch.Events[index];
		FILETIME fileTime;
		SYSTEMTIME time = { 0 };
		const char* action = event->Action == ND_ACTION_BLOCK ? "BLOCK" :
			event->Action == ND_ACTION_NO_RIGHT ? "NO-RIGHT" : "CONTINUE";

		fileTime.dwLowDateTime = (DWORD)event->Timestamp;
		fileTime.dwHighDateTime = (DWORD)(event->Timestamp >> 32);
		if (FileTimeToSystemTime(&fileTime, &time)) {
			printf("%04u-%02u-%02uT%02u:%02u:%02u.%03uZ ", time.wYear, time.wMonth,
				time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
		}
		printf("#%llu pid=%llu %s %s local=", event->Sequence, event->ProcessId,
			NdDirection(event->Endpoint.Direction), NdProtocol(event->Endpoint.Protocol));
		NdPrintAddress(event->Endpoint.LocalAddress);
		printf(":%lu remote=", event->Endpoint.LocalPort);
		NdPrintAddress(event->Endpoint.RemoteAddress);
		printf(":%lu %s\n", event->Endpoint.RemotePort, action);
	}
	return 0;
}

static BOOL WINAPI NdConsoleHandler(DWORD Event)
{
	if (Event == CTRL_C_EVENT || Event == CTRL_BREAK_EVENT) {
		InterlockedExchange(&g_Stop, 1);
		return TRUE;
	}
	return FALSE;
}

int main(int argc, char** argv)
{
	ND_RULE rule = { 0 };
	HANDLE device;
	DWORD returned = 0;
	DWORD access = GENERIC_READ;
	int setRule = 0;
	int watch = 0;
	int result = 0;
	ULONG count = 0;

	rule.Version = ND_VERSION;
	rule.Size = sizeof(rule);
	if (argc == 2 && (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0)) {
		NdUsage();
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "monitor") == 0) {
		setRule = 1;
	} else if (argc == 6 && strcmp(argv[1], "block") == 0) {
		if (!NdParseRule(&argv[2], &rule)) {
			fputs("Invalid rule. Specify a valid remote IPv4 and/or port; block-all is rejected.\n", stderr);
			return 2;
		}
		setRule = 1;
	} else if (argc == 2 && (strcmp(argv[1], "stats") == 0 || strcmp(argv[1], "events") == 0 ||
		strcmp(argv[1], "watch") == 0)) {
		watch = strcmp(argv[1], "watch") == 0;
	} else {
		NdUsage();
		return 2;
	}

	if (setRule) {
		access |= GENERIC_WRITE;
	}
	// Do not self-elevate or install a service implicitly. The kernel ACL is the
	// security boundary; the user intentionally opens an elevated terminal.
	device = CreateFileW(ND_DEVICE_USER, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (device == INVALID_HANDLE_VALUE) {
		fputs("Use an elevated terminal and verify the NetworkDriver service is running.\n", stderr);
		return NdError("Open driver");
	}

	if (setRule) {
		if (!DeviceIoControl(device, IOCTL_ND_SET_RULE, &rule, sizeof(rule), NULL, 0, &returned, NULL)) {
			result = NdError("SET_RULE");
		} else {
			puts(rule.Enabled ? "Block rule installed for future authorizations." : "Monitor-only mode restored.");
			result = NdPrintStats(device);
		}
	} else if (strcmp(argv[1], "stats") == 0) {
		result = NdPrintStats(device);
	} else {
		if (watch && !SetConsoleCtrlHandler(NdConsoleHandler, TRUE)) {
			result = NdError("SetConsoleCtrlHandler");
		} else {
			do {
				result = NdReadEvents(device, &count);
				if (result != 0 || !watch) {
					break;
				}
				if (count == 0) {
					Sleep(250);
				}
			} while (InterlockedCompareExchange(&g_Stop, 0, 0) == 0);
			if (watch) {
				SetConsoleCtrlHandler(NdConsoleHandler, FALSE);
			}
		}
	}
	CloseHandle(device);
	return result;
}
