/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
  "time"
)

func Uint64ToTimestamp(timestamp uint64) time.Time {
  return time.Unix(int64(timestamp/1000), int64(timestamp%1000))
}
