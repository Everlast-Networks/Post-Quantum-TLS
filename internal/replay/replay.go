// ---------------------------------------------------------------------------
// Copyright (c) 2026 Everlast Networks Pty. Ltd..
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" basis,
// without warranties or conditions of any kind, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ---------------------------------------------------------------------------

package replay

import (
    "sync"
    "time"
)

type Cache struct {
    mu sync.Mutex
    ttl time.Duration
    max int
    m map[[16]byte]int64 // id -> unix milli
}

func New(ttl time.Duration, maxEntries int) *Cache {
    if maxEntries <= 0 {
        maxEntries = 200000
    }
    return &Cache{
        ttl: ttl,
        max: maxEntries,
        m: make(map[[16]byte]int64, maxEntries/4),
    }
}

// SeenBefore returns true when the replay ID already exists within the TTL window.
func (c *Cache) SeenBefore(id [16]byte, nowMillis int64) bool {
    c.mu.Lock()
    defer c.mu.Unlock()

    // opportunistic prune; avoids dedicated goroutine
    if len(c.m) > c.max {
        c.pruneLocked(nowMillis)
    }

    if ts, ok := c.m[id]; ok {
        if nowMillis-ts <= c.ttl.Milliseconds() {
            return true
        }
    }
    c.m[id] = nowMillis
    return false
}

func (c *Cache) pruneLocked(nowMillis int64) {
    cutoff := nowMillis - c.ttl.Milliseconds()
    for k, ts := range c.m {
        if ts < cutoff {
            delete(c.m, k)
        }
    }
    // If still too large, hard trim by arbitrary deletes.
    for len(c.m) > c.max {
        for k := range c.m {
            delete(c.m, k)
            break
        }
    }
}
