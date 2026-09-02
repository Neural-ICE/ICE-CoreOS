#!/bin/sh
# shellcheck shell=sh
#
# THE ONE PARSER FOR `tpm2_nvreadpublic` OUTPUT.
#
# WHY THIS FILE EXISTS (review 2026-09-02, P0). The initramfs high-water hook
# read the attribute word off the `attributes:` heading itself, while tpm2-tools
# prints it on a NESTED line; its test mock emitted the flat shape the hook
# expected, so the suite was green and every real TPM root unlock would have
# been refused. A second parser is a second answer, and only one of them runs
# inside the signed UKI -- so the OTA helper and the initramfs hook now share
# this file, and the mocks render the exact shape tpm2-tools prints.
#
# THE CONTRACT, from tpm2-tools 5.7 tools/tpm2_nvreadpublic.c print_nv_public()
# (the version the centos-bootc:stream10 base ships):
#
#   0x%x:                          index, unpadded hex
#     name: %02x...                lowercase, 000b + 64 hex for SHA-256
#     hash algorithm:
#       friendly: %s
#       value: 0x%X
#     attributes:
#       friendly: %s
#       value: 0x%X                THE ATTRIBUTE WORD
#     size: %d
#     authorization policy: %02X...  uppercase; the line is absent when empty
#
# It is POSIX sh + POSIX awk on purpose: it runs in the initramfs /bin/sh and
# is sourced by bash in the OTA helper.
#
# ni_tpm2_nv_public_parse <expected-index>
#   stdin   the complete output of `tpm2_nvreadpublic <index>`
#   stdout  one line on success: <attributes> <size> <policy> <name>
#           attributes as 0x + lowercase hex, policy and name as lowercase hex
#   exit    0 on success; 1 with the reason on stderr for ANY deviation: no or
#           several index blocks, another index, a missing, repeated or
#           malformed field, the legacy flat `attributes: 0x..` form, a nested
#           value outside its section, an empty policy, or an unknown line.
ni_tpm2_nv_public_parse() {
  awk -v expected="$1" '
    function fail(reason) {
      printf "tpm2_nvreadpublic output refused: %s\n", reason > "/dev/stderr"
      exit 1
    }
    function canonical_index(value) {
      value = tolower(value)
      sub(/^0x/, "", value)
      sub(/^0+/, "", value)
      return value == "" ? "0" : value
    }
    BEGIN {
      if (expected !~ /^0[xX][0-9a-fA-F]+$/) fail("expected index is not hex")
      headers = 0; names = 0; sections = 0; values = 0; sizes = 0; policies = 0
      section = ""
    }
    /^$/ { next }
    /^0[xX][0-9a-fA-F]+:$/ {
      headers++
      if (headers > 1) fail("more than one index block")
      index_seen = substr($0, 1, length($0) - 1)
      if (canonical_index(index_seen) != canonical_index(expected))
        fail("index " index_seen " is not the expected " expected)
      section = ""
      next
    }
    headers == 0 { fail("field before the index header") }
    /^  name: [0-9a-fA-F]+$/ {
      names++
      name = tolower($2)
      if (name !~ /^000b[0-9a-f]+$/ || length(name) != 68) fail("name is not a SHA-256 public Name")
      section = ""
      next
    }
    /^  hash algorithm:$/ { section = "hash"; next }
    /^  attributes:$/ {
      sections++
      if (sections > 1) fail("attributes section repeated")
      section = "attributes"
      next
    }
    /^    friendly: [^ ].*$/ {
      if (section == "") fail("friendly line outside a section")
      next
    }
    /^    value: 0[xX][0-9a-fA-F]+$/ {
      if (section == "attributes") {
        values++
        if (values > 1) fail("attributes value repeated")
        attributes = tolower($2)
        if (length(attributes) > 10) fail("attributes value exceeds 32 bits")
      } else if (section != "hash") {
        fail("value line outside a section")
      }
      next
    }
    /^  size: (0|[1-9][0-9]*)$/ { sizes++; size = $2; section = ""; next }
    /^  authorization policy: [0-9a-fA-F]+$/ {
      policies++
      policy = tolower($3)
      if (length(policy) != 64) fail("authorization policy is not 32 bytes")
      section = ""
      next
    }
    { fail("unrecognised line: " $0) }
    END {
      if (headers != 1) fail("no index block")
      if (names != 1) fail("name absent or repeated")
      if (sections != 1) fail("attributes section absent")
      if (values != 1) fail("attributes value absent")
      if (sizes != 1) fail("size absent or repeated")
      if (policies != 1) fail("authorization policy absent, empty or repeated")
      printf "%s %s %s %s\n", attributes, size, policy, name
    }
  '
}
