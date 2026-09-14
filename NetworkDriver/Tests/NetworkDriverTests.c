#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "../Shared/NetworkRule.h"

static unsigned int g_Checks;
static unsigned int g_Failures;

// Unlike assert(), these checks still execute in Release builds.
#define CHECK(Expression) do { ++g_Checks; if (!(Expression)) { \
	++g_Failures; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); } } while (0)

static ND_RULE NdTestRule(void)
{
	ND_RULE rule = { 0 };
	rule.Version = ND_VERSION;
	rule.Size = sizeof(rule);
	return rule;
}

static void NdRuleTests(void)
{
	ND_RULE rule = NdTestRule();
	ND_RULE invalid;
	ND_ENDPOINT endpoint = { ND_DIRECTION_OUTBOUND, ND_PROTOCOL_TCP,
		0x7F000001, 0x7F000001, 50000, 8080 };
	ULONG index;
	const ULONG badProtocols[] = { 1, 5, 7, 16, 18, 255, ULONG_MAX };

	CHECK(sizeof(ND_RULE) == 32);
	CHECK(sizeof(ND_EVENT) == 56);
	CHECK(sizeof(ND_STATS) == 80);
	CHECK(sizeof(ND_EVENT_BATCH) == 1808);
	CHECK((IOCTL_ND_SET_RULE & 3) == METHOD_BUFFERED);
	CHECK(((IOCTL_ND_SET_RULE >> 14) & 3) == FILE_WRITE_ACCESS);
	CHECK(((IOCTL_ND_GET_STATS >> 14) & 3) == FILE_READ_ACCESS);
	CHECK(((IOCTL_ND_READ_EVENTS >> 14) & 3) == FILE_READ_ACCESS);
	CHECK(NdRuleValid(&rule));
	CHECK(!NdRuleMatches(&rule, &endpoint));
	rule.Enabled = 1;
	CHECK(!NdRuleValid(&rule));
	rule.ServicePort = 8080;
	CHECK(NdRuleValid(&rule));
	CHECK(NdRuleMatches(&rule, &endpoint));
	rule.ServicePort = 8081;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	rule.ServicePort = 8080;
	rule.Protocol = ND_PROTOCOL_UDP;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	endpoint.Protocol = ND_PROTOCOL_UDP;
	CHECK(NdRuleMatches(&rule, &endpoint));
	rule.Protocol = ND_PROTOCOL_ANY;
	rule.Direction = ND_DIRECTION_INBOUND;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	endpoint.Direction = ND_DIRECTION_INBOUND;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	endpoint.LocalPort = 8080;
	endpoint.RemotePort = 50000;
	CHECK(NdRuleMatches(&rule, &endpoint));
	rule.RemoteAddress = 0x7F000002;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	rule.RemoteAddress = 0x7F000001;
	CHECK(NdRuleMatches(&rule, &endpoint));
	rule.ServicePort = 0;
	CHECK(NdRuleValid(&rule));
	CHECK(NdRuleMatches(&rule, &endpoint));
	endpoint.Protocol = 1;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	endpoint.Protocol = ND_PROTOCOL_TCP;
	endpoint.Direction = 99;
	CHECK(!NdRuleMatches(&rule, &endpoint));
	endpoint.Direction = ND_DIRECTION_INBOUND;
	rule.Direction = ND_DIRECTION_ANY;
	CHECK(NdRuleMatches(&rule, &endpoint));
	rule.Enabled = 0;
	CHECK(!NdRuleMatches(&rule, &endpoint));

	invalid = rule; invalid.Version = 0; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.Version = ND_VERSION + 1; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.Size--; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.Size++; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.Reserved = 1; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.Enabled = 2; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.Direction = 3; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.ServicePort = 65536; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.ServicePort = ULONG_MAX; CHECK(!NdRuleValid(&invalid));
	invalid = rule; invalid.ServicePort = 65535; CHECK(NdRuleValid(&invalid));
	invalid = rule; invalid.ServicePort = 1; CHECK(NdRuleValid(&invalid));
	for (index = 0; index < ARRAYSIZE(badProtocols); ++index) {
		invalid = rule;
		invalid.Protocol = badProtocols[index];
		CHECK(!NdRuleValid(&invalid));
	}
}

static void NdDeviceTests(void)
{
	HANDLE readOnly;
	HANDLE writable;
	ND_RULE rule = NdTestRule();
	ND_STATS stats = { 0 };
	ND_STATS before = { 0 };
	DWORD returned = 0;
	BOOL success;

	// Explicit opt-in: requires the test-signed driver running in a VM. Never
	// install/start a service, clear policy, or submit a valid rule from tests.
	readOnly = CreateFileW(ND_DEVICE_USER, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);
	CHECK(readOnly != INVALID_HANDLE_VALUE);
	if (readOnly == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Open failed: %lu. Run elevated in the prepared VM.\n", GetLastError());
		return;
	}
	CHECK(DeviceIoControl(readOnly, IOCTL_ND_GET_STATS, NULL, 0, &before, sizeof(before), &returned, NULL));
	CHECK(returned == sizeof(before));
	CHECK(before.Version == ND_VERSION && before.Size == sizeof(before));
	CHECK(before.Capacity == ND_EVENT_CAPACITY && before.Queued <= before.Capacity);
	CHECK(NdRuleValid(&before.Rule));

	success = DeviceIoControl(readOnly, IOCTL_ND_SET_RULE, &rule, sizeof(rule), NULL, 0, &returned, NULL);
	CHECK(!success);
	CHECK(GetLastError() == ERROR_ACCESS_DENIED);
	CHECK(!DeviceIoControl(readOnly, IOCTL_ND_GET_STATS, NULL, 0, &stats, sizeof(stats) - 1, &returned, NULL));
	CHECK(returned == 0);
	CHECK(!DeviceIoControl(readOnly, IOCTL_ND_GET_STATS, &rule, sizeof(rule), &stats, sizeof(stats), &returned, NULL));
	CHECK(!DeviceIoControl(readOnly, IOCTL_ND_READ_EVENTS, NULL, 0, &stats, sizeof(stats), &returned, NULL));
	CHECK(!DeviceIoControl(readOnly, CTL_CODE(ND_DEVICE_TYPE, 0xFFF, METHOD_BUFFERED, FILE_READ_ACCESS),
		NULL, 0, NULL, 0, &returned, NULL));

	writable = CreateFileW(ND_DEVICE_USER, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);
	CHECK(writable != INVALID_HANDLE_VALUE);
	if (writable != INVALID_HANDLE_VALUE) {
		CHECK(!DeviceIoControl(writable, IOCTL_ND_SET_RULE, NULL, 0, NULL, 0, &returned, NULL));
		CHECK(!DeviceIoControl(writable, IOCTL_ND_SET_RULE, &rule, sizeof(rule) - 1, NULL, 0, &returned, NULL));
		rule.Version++;
		CHECK(!DeviceIoControl(writable, IOCTL_ND_SET_RULE, &rule, sizeof(rule), NULL, 0, &returned, NULL));
		rule = NdTestRule(); rule.Enabled = 1;
		CHECK(!DeviceIoControl(writable, IOCTL_ND_SET_RULE, &rule, sizeof(rule), NULL, 0, &returned, NULL));
		rule.ServicePort = 65536;
		CHECK(!DeviceIoControl(writable, IOCTL_ND_SET_RULE, &rule, sizeof(rule), NULL, 0, &returned, NULL));
		CHECK(DeviceIoControl(writable, IOCTL_ND_GET_STATS, NULL, 0, &stats, sizeof(stats), &returned, NULL));
		CHECK(memcmp(&stats.Rule, &before.Rule, sizeof(stats.Rule)) == 0);
		CloseHandle(writable);
	}
	CloseHandle(readOnly);
}

static int NdWaitSocket(SOCKET Socket, int Write)
{
	fd_set ready;
	fd_set errors;
	struct timeval timeout = { 5, 0 };
	int result;

	FD_ZERO(&ready);
	FD_ZERO(&errors);
	FD_SET(Socket, &ready);
	FD_SET(Socket, &errors);
	result = select(0, Write ? NULL : &ready, Write ? &ready : NULL, &errors, &timeout);
	if (result <= 0 || FD_ISSET(Socket, &errors)) {
		fputs("Socket error or five-second timeout (a block is one possible cause).\n", stderr);
		return 0;
	}
	return 1;
}

static int NdFixture(int argc, char** argv)
{
	WSADATA data;
	struct sockaddr_in address = { 0 };
	struct sockaddr_in peer = { 0 };
	SOCKET socketHandle = INVALID_SOCKET;
	SOCKET accepted = INVALID_SOCKET;
	SOCKET connection;
	int peerLength = sizeof(peer);
	int listenMode;
	int udp;
	int result = 1;
	int received;
	int socketError = 0;
	int errorLength = sizeof(socketError);
	u_long nonblocking = 1;
	DWORD timeout = 5000;
	char buffer[2];
	const char message[2] = { 'N', 'D' };
	const char* digit;
	ULONG port = 0;

	if (argc != 5 || (strcmp(argv[1], "listen") != 0 && strcmp(argv[1], "probe") != 0) ||
		(strcmp(argv[2], "tcp") != 0 && strcmp(argv[2], "udp") != 0)) {
		fputs("Fixture: NetworkDriverTests <listen|probe> <tcp|udp> <IPv4> <port>\n", stderr);
		return 2;
	}
	listenMode = strcmp(argv[1], "listen") == 0;
	udp = strcmp(argv[2], "udp") == 0;
	for (digit = argv[4]; *digit != '\0'; ++digit) {
		if (*digit < '0' || *digit > '9') { return 2; }
		port = port * 10 + (ULONG)(*digit - '0');
		if (port > 65535) { return 2; }
	}
	if (port == 0 || InetPtonA(AF_INET, argv[3], &address.sin_addr) != 1 ||
		address.sin_addr.S_un.S_addr == 0) {
		fputs("Use an explicit local/private IPv4 address and port 1-65535.\n", stderr);
		return 2;
	}
	address.sin_family = AF_INET;
	address.sin_port = htons((USHORT)port);
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) { return 1; }
	socketHandle = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP);
	if (socketHandle == INVALID_SOCKET) { goto Cleanup; }
	// The fixture also has bounded send/receive waits; a test must not hang when blocked.
	if (setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0 ||
		setsockopt(socketHandle, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
		goto Cleanup;
	}

	if (listenMode) {
		BOOL exclusive = TRUE;
		if (setsockopt(socketHandle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&exclusive, sizeof(exclusive)) != 0 ||
			bind(socketHandle, (const struct sockaddr*)&address, sizeof(address)) != 0) { goto Cleanup; }
		if (!udp && listen(socketHandle, 1) != 0) { goto Cleanup; }
		puts("Ready for one echo exchange (five-second timeout). Start probe in another terminal.");
		if (!NdWaitSocket(socketHandle, 0)) { goto Cleanup; }
		if (udp) {
			received = recvfrom(socketHandle, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer, &peerLength);
			if (received == sizeof(message) && memcmp(buffer, message, sizeof(message)) == 0 &&
				sendto(socketHandle, buffer, received, 0, (const struct sockaddr*)&peer, peerLength) == received) {
				result = 0;
			}
		} else {
			accepted = accept(socketHandle, NULL, NULL);
			if (accepted == INVALID_SOCKET) { goto Cleanup; }
			if (setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0 ||
				setsockopt(accepted, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) { goto Cleanup; }
			received = recv(accepted, buffer, sizeof(buffer), MSG_WAITALL);
			if (received == sizeof(message) && memcmp(buffer, message, sizeof(message)) == 0 &&
				send(accepted, buffer, received, 0) == received) { result = 0; }
		}
	} else {
		// Nonblocking connect + select avoids the OS's long TCP retry timeout.
		if (ioctlsocket(socketHandle, FIONBIO, &nonblocking) != 0) { goto Cleanup; }
		if (connect(socketHandle, (const struct sockaddr*)&address, sizeof(address)) != 0) {
			if (WSAGetLastError() != WSAEWOULDBLOCK || !NdWaitSocket(socketHandle, 1) ||
				getsockopt(socketHandle, SOL_SOCKET, SO_ERROR, (char*)&socketError, &errorLength) != 0 || socketError != 0) {
				goto Cleanup;
			}
		}
		nonblocking = 0;
		if (ioctlsocket(socketHandle, FIONBIO, &nonblocking) != 0) { goto Cleanup; }
		connection = socketHandle;
		if (send(connection, message, sizeof(message), 0) != sizeof(message) || !NdWaitSocket(connection, 0)) { goto Cleanup; }
		received = recv(connection, buffer, sizeof(buffer), udp ? 0 : MSG_WAITALL);
		if (received == sizeof(message) && memcmp(buffer, message, sizeof(message)) == 0) { result = 0; }
	}

Cleanup:
	if (result != 0) {
		fprintf(stderr, "Echo failed; WSA error=%d. Check listener, firewall, and driver events.\n", WSAGetLastError());
	} else {
		puts("Echo succeeded.");
	}
	if (accepted != INVALID_SOCKET) { closesocket(accepted); }
	if (socketHandle != INVALID_SOCKET) { closesocket(socketHandle); }
	WSACleanup();
	return result;
}

int main(int argc, char** argv)
{
	if (argc > 1 && (strcmp(argv[1], "listen") == 0 || strcmp(argv[1], "probe") == 0)) {
		return NdFixture(argc, argv);
	}
	if (argc > 2 || (argc == 2 && strcmp(argv[1], "--device") != 0)) {
		fputs("Usage: NetworkDriverTests [--device]\nOr: NetworkDriverTests <listen|probe> <tcp|udp> <IPv4> <port>\n", stderr);
		return 2;
	}
	NdRuleTests();
	if (argc == 2) {
		NdDeviceTests();
	}
	printf("%u checks, %u failures.\n", g_Checks, g_Failures);
	return g_Failures == 0 ? 0 : 1;
}
