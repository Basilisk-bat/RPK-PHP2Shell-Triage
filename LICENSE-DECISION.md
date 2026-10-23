# License decision for the public candidate

The accountable owner selected Apache License 2.0 for the RPK-authored contributions on 2026-10-22. The operative [LICENSE](LICENSE) contains that license. The upstream MIT notice in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) continues to apply to the adapted Eric Mann material identified in [PROVENANCE.md](PROVENANCE.md). The package metadata uses `Apache-2.0 AND MIT` to identify both license obligations in the distributed source. This decision does not assert that RPK owns or relicenses the upstream work.

## Evidence inspected

- The owner-controlled public [RPK-PHP-CGI-Lab](https://github.com/Basilisk-bat/RPK-PHP-CGI-Lab/blob/main/LICENSE) and [RPK-php2shell-checker](https://github.com/Basilisk-bat/RPK-php2shell-checker/blob/main/LICENSE) repositories each contain an Apache License 2.0 file. The owner separately chose Apache License 2.0 for the original contributions in this candidate.
- [ericmann/php2shell-ioc at commit `7b099c1a87798bf29867a1c2c5bbf10f238d89af`](https://github.com/ericmann/php2shell-ioc/blob/7b099c1a87798bf29867a1c2c5bbf10f238d89af/LICENSE) carries the MIT License and `Copyright (c) 2026 Eric Mann`. The candidate adapts compact IOC regex alternatives and synthetic test examples from that source. Its full notice is preserved byte-for-byte in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); keep that notice with any release containing the adapted material.

## Publication boundary

Keep both license texts and this provenance record with any public source or package distribution. Recheck the exact files and wheel before each release. The license choice alone does not authorize a specific GitHub publication or package upload.
