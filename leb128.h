/*
==============================================================================
LLVM Release License
==============================================================================
University of Illinois/NCSA
Open Source License

Copyright (c) 2003-2010 University of Illinois at Urbana-Champaign.
All rights reserved.

Developed by:

    LLVM Team

    University of Illinois at Urbana-Champaign

    http://llvm.org

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal with
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimers.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimers in the
      documentation and/or other materials provided with the distribution.

    * Neither the names of the LLVM Team, University of Illinois at
      Urbana-Champaign, nor the names of its contributors may be used to
      endorse or promote products derived from this Software without specific
      prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE
SOFTWARE.
*/

#ifndef LEB128_H
#define LEB128_H

/// Utility function to decode a ULEB128 value.
static uint64_t decodeULEB128(const uint8_t *p, unsigned *n,
                              const uint8_t *end,
                              const char **error) {
  const uint8_t *orig_p = p;
  uint64_t Value = 0;
  unsigned Shift = 0;
  if (error)
    *error = NULL;
  do {
    if (end && p == end) {
      if (error)
        *error = "malformed uleb128, extends past end";
      if (n)
        *n = (unsigned)(p - orig_p);
      return 0;
    }
    uint64_t Slice = *p & 0x7f;
    if (Shift >= 64 || Slice << Shift >> Shift != Slice) {
      if (error)
        *error = "uleb128 too big for uint64";
      if (n)
        *n = (unsigned)(p - orig_p);
      return 0;
    }
    Value += (uint64_t)(*p & 0x7f) << Shift;
    Shift += 7;
  } while (*p++ >= 128);
  if (n)
    *n = (unsigned)(p - orig_p);
  return Value;
}

/// Utility function to decode a SLEB128 value.
static int64_t decodeSLEB128(const uint8_t *p, unsigned *n,
                             const uint8_t *end,
                             const char **error) {
  const uint8_t *orig_p = p;
  int64_t Value = 0;
  unsigned Shift = 0;
  uint8_t Byte;
  do {
    if (end && p == end) {
      if (error)
        *error = "malformed sleb128, extends past end";
      if (n)
        *n = (unsigned)(p - orig_p);
      return 0;
    }
    Byte = *p++;
    Value |= ((int64_t)(Byte & 0x7f) << Shift);
    Shift += 7;
  } while (Byte >= 128);
  // Sign extend negative numbers.
  if (Byte & 0x40)
    Value |= (-1ULL) << Shift;
  if (n)
    *n = (unsigned)(p - orig_p);
  return Value;
}

#endif // LEB128_H
