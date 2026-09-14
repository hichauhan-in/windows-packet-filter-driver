#pragma once
#include "NetworkDriverShared.h"

// These functions do not allocate, block or call kernel APIs. Keeping the policy
// separate lets the exact kernel matching code run in ordinary user-mode tests.
static __inline int NdRuleValid(const ND_RULE* Rule)
{
	if (Rule->Version != ND_VERSION || Rule->Size != sizeof(ND_RULE) ||
		Rule->Enabled > 1 || Rule->Reserved != 0 ||
		Rule->Direction > ND_DIRECTION_INBOUND || Rule->ServicePort > 65535) {
		return 0;
	}

	if (Rule->Protocol != ND_PROTOCOL_ANY && Rule->Protocol != ND_PROTOCOL_TCP &&
		Rule->Protocol != ND_PROTOCOL_UDP) {
		return 0;
	}

	return !Rule->Enabled || Rule->RemoteAddress != 0 || Rule->ServicePort != 0;
}

static __inline int NdRuleMatches(const ND_RULE* Rule, const ND_ENDPOINT* Endpoint)
{
	ULONG servicePort;

	if (!Rule->Enabled ||
		(Endpoint->Direction != ND_DIRECTION_OUTBOUND && Endpoint->Direction != ND_DIRECTION_INBOUND) ||
		(Endpoint->Protocol != ND_PROTOCOL_TCP && Endpoint->Protocol != ND_PROTOCOL_UDP)) {
		return 0;
	}

	servicePort = Endpoint->Direction == ND_DIRECTION_OUTBOUND ?
		Endpoint->RemotePort : Endpoint->LocalPort;

	return (Rule->Direction == ND_DIRECTION_ANY || Rule->Direction == Endpoint->Direction) &&
		(Rule->Protocol == ND_PROTOCOL_ANY || Rule->Protocol == Endpoint->Protocol) &&
		(Rule->RemoteAddress == 0 || Rule->RemoteAddress == Endpoint->RemoteAddress) &&
		(Rule->ServicePort == 0 || Rule->ServicePort == servicePort);
}
