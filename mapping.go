// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package portmap

import (
	"context"
	"net/netip"
	"time"
)

// Mapping represents a created port-mapping over some protocol.  It specifies a lease duration,
// how to release the mapping, and whether the map is still valid.
//
// After a mapping is created, it should be immutable, and thus reads should be safe across
// concurrent goroutines.
type Mapping interface {
	// Release will attempt to unmap the established port mapping. It will block until completion,
	// but can be called asynchronously. Release should be idempotent, and thus even if called
	// multiple times should not cause additional side-effects.
	Release(context.Context)

	// GoodUntil will return the lease time that the mapping is valid for.
	GoodUntil() time.Time

	// RenewAfter returns the earliest time that the mapping should be renewed.
	RenewAfter() time.Time

	// External indicates what port the mapping can be reached from on the outside.
	External() netip.AddrPort
}
