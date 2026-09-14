#include <ntddk.h>
#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>
#include <wdmsec.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "Shared/NetworkRule.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD NdUnload;
DRIVER_DISPATCH NdCreateClose;
DRIVER_DISPATCH NdUnsupported;
DRIVER_DISPATCH NdDeviceControl;

// Private GUIDs isolate this sample from other WFP providers and device classes.
DEFINE_GUID(ND_DEVICE_CLASS, 0xb4d65ca1, 0x8893, 0x4f30, 0x93, 0xbd, 0xa2, 0x2e, 0x84, 0x62, 0x3d, 0x10);
DEFINE_GUID(ND_SUBLAYER, 0xb4d65ca2, 0x8893, 0x4f30, 0x93, 0xbd, 0xa2, 0x2e, 0x84, 0x62, 0x3d, 0x10);
DEFINE_GUID(ND_OUTBOUND_CALLOUT, 0xb4d65ca3, 0x8893, 0x4f30, 0x93, 0xbd, 0xa2, 0x2e, 0x84, 0x62, 0x3d, 0x10);
DEFINE_GUID(ND_INBOUND_CALLOUT, 0xb4d65ca4, 0x8893, 0x4f30, 0x93, 0xbd, 0xa2, 0x2e, 0x84, 0x62, 0x3d, 0x10);

static PDEVICE_OBJECT g_Device;
static HANDLE g_Engine;
static UINT32 g_CalloutIds[2];
static BOOLEAN g_LinkCreated;

// Classify can run at DISPATCH_LEVEL on multiple CPUs. Static storage is nonpaged;
// one short spin lock protects the rule, counters and bounded event ring together.
// No allocation, file I/O, waiting, or per-event debug printing in this path.
static KSPIN_LOCK g_StateLock;
static ND_STATS g_Stats;
static ND_EVENT g_Events[ND_EVENT_CAPACITY];
static ULONG g_Head;

static NTSTATUS NdComplete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS NdUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return NdComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

NTSTATUS NdCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	// This is a control endpoint, not a filesystem. Reject names below the device.
	if (stack->MajorFunction == IRP_MJ_CREATE && stack->FileObject->FileName.Length != 0) {
		return NdComplete(Irp, STATUS_OBJECT_NAME_NOT_FOUND, 0);
	}
	return NdComplete(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS NdDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG_PTR information = 0;
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	ULONG index;
	ND_RULE rule;
	ND_EVENT_BATCH* batch;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Each successful request completes inline. No pending IRP survives unload.
	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_ND_SET_RULE:
		if (inputLength != sizeof(ND_RULE) || buffer == NULL) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		RtlCopyMemory(&rule, buffer, sizeof(rule));
		if (!NdRuleValid(&rule)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		KeAcquireSpinLock(&g_StateLock, &oldIrql);
		g_Stats.Rule = rule;
		KeReleaseSpinLock(&g_StateLock, oldIrql);
		break;

	case IOCTL_ND_GET_STATS:
		if (inputLength != 0 || outputLength < sizeof(ND_STATS) || buffer == NULL) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		KeAcquireSpinLock(&g_StateLock, &oldIrql);
		RtlCopyMemory(buffer, &g_Stats, sizeof(g_Stats));
		KeReleaseSpinLock(&g_StateLock, oldIrql);
		information = sizeof(ND_STATS);
		break;

	case IOCTL_ND_READ_EVENTS:
		if (inputLength != 0 || outputLength < sizeof(ND_EVENT_BATCH) || buffer == NULL) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		batch = (ND_EVENT_BATCH*)buffer;
		// Zero the entire returned ABI, including unused slots and reserved fields.
		// Otherwise a buffered IOCTL can accidentally disclose kernel memory.
		RtlZeroMemory(batch, sizeof(*batch));
		batch->Version = ND_VERSION;
		batch->Size = sizeof(*batch);
		KeAcquireSpinLock(&g_StateLock, &oldIrql);
		batch->Count = min(g_Stats.Queued, ND_BATCH_CAPACITY);
		for (index = 0; index < batch->Count; ++index) {
			batch->Events[index] = g_Events[g_Head];
			g_Head = (g_Head + 1) % ND_EVENT_CAPACITY;
		}
		g_Stats.Queued -= batch->Count;
		KeReleaseSpinLock(&g_StateLock, oldIrql);
		information = sizeof(*batch);
		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	return NdComplete(Irp, status, information);
}

void NTAPI NdClassify(
	const FWPS_INCOMING_VALUES0* Values,
	const FWPS_INCOMING_METADATA_VALUES0* Metadata,
	void* LayerData,
	const FWPS_FILTER0* Filter,
	UINT64 FlowContext,
	FWPS_CLASSIFY_OUT0* ClassifyOut)
{
	ND_EVENT event = { 0 };
	LARGE_INTEGER timestamp;
	KIRQL oldIrql;
	ULONG tail;
	BOOLEAN canWrite;

	UNREFERENCED_PARAMETER(LayerData);
	UNREFERENCED_PARAMETER(Filter);
	UNREFERENCED_PARAMETER(FlowContext);

	// WFP supplies typed, host-order fields at these ALE layers. We do not cast
	// packet buffers or assume that an IP/TCP header is contiguous in memory.
	if (Values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
		event.Endpoint.Direction = ND_DIRECTION_OUTBOUND;
		event.Endpoint.Protocol = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
		event.Endpoint.LocalAddress = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
		event.Endpoint.RemoteAddress = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
		event.Endpoint.LocalPort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
		event.Endpoint.RemotePort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
	} else if (Values->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
		event.Endpoint.Direction = ND_DIRECTION_INBOUND;
		event.Endpoint.Protocol = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
		event.Endpoint.LocalAddress = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
		event.Endpoint.RemoteAddress = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
		event.Endpoint.LocalPort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
		event.Endpoint.RemotePort = Values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
	} else {
		if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
			ClassifyOut->actionType = FWP_ACTION_CONTINUE;
		}
		return;
	}

	if (FWPS_IS_METADATA_FIELD_PRESENT(Metadata, FWPS_METADATA_FIELD_PROCESS_ID)) {
		event.ProcessId = Metadata->processId;
	}
	KeQuerySystemTime(&timestamp);
	event.Timestamp = (ULONGLONG)timestamp.QuadPart;
	canWrite = (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0;

	KeAcquireSpinLock(&g_StateLock, &oldIrql);
	event.Sequence = ++g_Stats.Observed;
	if (!canWrite) {
		// Another WFP decision owns the action. Never overwrite it.
		event.Action = ND_ACTION_NO_RIGHT;
		++g_Stats.NoActionRight;
	} else if (NdRuleMatches(&g_Stats.Rule, &event.Endpoint)) {
		event.Action = ND_ACTION_BLOCK;
		++g_Stats.Blocked;
		ClassifyOut->actionType = FWP_ACTION_BLOCK;
		ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	} else {
		event.Action = ND_ACTION_CONTINUE;
		// CONTINUE is deliberately not PERMIT: Windows Firewall and other
		// providers must still be allowed to inspect or reject this connection.
		ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	if (g_Stats.Queued == ND_EVENT_CAPACITY) {
		g_Head = (g_Head + 1) % ND_EVENT_CAPACITY;
		--g_Stats.Queued;
		++g_Stats.Overwritten;
	}
	tail = (g_Head + g_Stats.Queued) % ND_EVENT_CAPACITY;
	g_Events[tail] = event;
	++g_Stats.Queued;
	KeReleaseSpinLock(&g_StateLock, oldIrql);
}

NTSTATUS NTAPI NdNotify(FWPS_CALLOUT_NOTIFY_TYPE NotifyType, const GUID* FilterKey, FWPS_FILTER0* Filter)
{
	UNREFERENCED_PARAMETER(NotifyType);
	UNREFERENCED_PARAMETER(FilterKey);
	UNREFERENCED_PARAMETER(Filter);
	return STATUS_SUCCESS;
}

static NTSTATUS NdAddLayer(const GUID* Layer, const GUID* CalloutKey, UINT32* RuntimeId)
{
	FWPS_CALLOUT0 runtimeCallout = { 0 };
	FWPM_CALLOUT0 managementCallout = { 0 };
	FWPM_FILTER0 filter = { 0 };
	FWPM_FILTER_CONDITION0 condition = { 0 };
	NTSTATUS status;
	ULONG index;
	const UINT8 protocols[] = { ND_PROTOCOL_TCP, ND_PROTOCOL_UDP };

	// Runtime registration supplies function pointers. Management registration
	// connects a GUID to a WFP layer; a filter makes WFP actually invoke it.
	runtimeCallout.calloutKey = *CalloutKey;
	runtimeCallout.classifyFn = NdClassify;
	runtimeCallout.notifyFn = NdNotify;
	status = FwpsCalloutRegister0(g_Device, &runtimeCallout, RuntimeId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	managementCallout.calloutKey = *CalloutKey;
	managementCallout.displayData.name = L"NetworkDriver IPv4 authorization";
	managementCallout.applicableLayer = *Layer;
	status = FwpmCalloutAdd0(g_Engine, &managementCallout, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	filter.displayData.name = L"NetworkDriver TCP/UDP metadata filter";
	filter.layerKey = *Layer;
	filter.subLayerKey = ND_SUBLAYER;
	filter.weight.type = FWP_EMPTY;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = *CalloutKey;
	// If runtime registration disappears, this sample must not strand a block
	// filter. Normal unload still removes the dynamic filters before unregistering.
	filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
	filter.numFilterConditions = 1;
	filter.filterCondition = &condition;
	condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	condition.matchType = FWP_MATCH_EQUAL;
	condition.conditionValue.type = FWP_UINT8;

	for (index = 0; index < RTL_NUMBER_OF(protocols); ++index) {
		condition.conditionValue.uint8 = protocols[index];
		status = FwpmFilterAdd0(g_Engine, &filter, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			return status;
		}
	}
	return STATUS_SUCCESS;
}

static NTSTATUS NdStartFiltering(void)
{
	FWPM_SESSION0 session = { 0 };
	FWPM_SUBLAYER0 sublayer = { 0 };
	NTSTATUS status;

	// Dynamic WFP objects belong to this handle and are removed on close. A
	// transaction prevents a failed startup from leaving half a policy installed.
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.displayData.name = L"NetworkDriver lab session";
	status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_Engine);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = FwpmTransactionBegin0(g_Engine, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	sublayer.subLayerKey = ND_SUBLAYER;
	sublayer.displayData.name = L"NetworkDriver lab sublayer";
	sublayer.weight = 0x100;
	status = FwpmSubLayerAdd0(g_Engine, &sublayer, NULL);
	if (NT_SUCCESS(status)) {
		status = NdAddLayer(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &ND_OUTBOUND_CALLOUT, &g_CalloutIds[0]);
	}
	if (NT_SUCCESS(status)) {
		status = NdAddLayer(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &ND_INBOUND_CALLOUT, &g_CalloutIds[1]);
	}
	if (NT_SUCCESS(status)) {
		status = FwpmTransactionCommit0(g_Engine);
	}
	if (!NT_SUCCESS(status)) {
		FwpmTransactionAbort0(g_Engine);
	}
	return status;
}

static void NdCleanup(void)
{
	UNICODE_STRING linkName = RTL_CONSTANT_STRING(ND_DEVICE_DOS);
	ULONG index;

	if (g_LinkCreated) {
		IoDeleteSymbolicLink(&linkName);
		g_LinkCreated = FALSE;
	}
	if (g_Engine != NULL) {
		FwpmEngineClose0(g_Engine);
		g_Engine = NULL;
	}
	// Unregister waits for in-flight callbacks. Only then can device state go away.
	// This driver has no flow contexts or asynchronous work to keep references alive.
	for (index = 0; index < RTL_NUMBER_OF(g_CalloutIds); ++index) {
		if (g_CalloutIds[index] != 0) {
			FwpsCalloutUnregisterById0(g_CalloutIds[index]);
			g_CalloutIds[index] = 0;
		}
	}
	if (g_Device != NULL) {
		IoDeleteDevice(g_Device);
		g_Device = NULL;
	}
}

void NdUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	NdCleanup();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NetworkDriver: unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(ND_DEVICE_NT);
	UNICODE_STRING linkName = RTL_CONSTANT_STRING(ND_DEVICE_DOS);
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	NTSTATUS status;
	ULONG index;

	UNREFERENCED_PARAMETER(RegistryPath);
	KeInitializeSpinLock(&g_StateLock);
	g_Stats.Version = ND_VERSION;
	g_Stats.Size = sizeof(g_Stats);
	g_Stats.Rule.Version = ND_VERSION;
	g_Stats.Rule.Size = sizeof(g_Stats.Rule);
	g_Stats.Capacity = ND_EVENT_CAPACITY;

	for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
		DriverObject->MajorFunction[index] = NdUnsupported;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = NdCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = NdCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = NdCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NdDeviceControl;
	DriverObject->DriverUnload = NdUnload;

	// A named device requires an explicit ACL. Protected DACL grants access only
	// to LocalSystem and elevated Builtin Administrators, including read access.
	status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, ND_DEVICE_TYPE,
		FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &ND_DEVICE_CLASS, &g_Device);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = NdStartFiltering();
	if (NT_SUCCESS(status)) {
		status = IoCreateSymbolicLink(&linkName, &deviceName);
		if (NT_SUCCESS(status)) {
			g_LinkCreated = TRUE;
		}
	}
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"NetworkDriver: initialization failed (0x%08lX)\n", (ULONG)status);
		NdCleanup();
		return status;
	}
	g_Device->Flags &= ~DO_DEVICE_INITIALIZING;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NetworkDriver: monitor-only mode\n");
	return STATUS_SUCCESS;
}
