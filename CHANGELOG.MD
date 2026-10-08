# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.10]

### Added

- Added object class descriptions to the connector schema. For Active Directory, descriptions use `adminDescription`, falling back to `description`.
- Added a Jenkins build pipeline and Maven profiles for CycloneDX SBOM generation and upload to Dependency-Track.

### Changed

- Included both `groupOfNames` and `groupOfUniqueNames` in the default group object class configuration.
- Improved managed association suggestions by prioritizing common association pairs, sorting remaining object classes alphabetically, and removing duplicate suggestions.
- Improved OpenLDAP configuration suggestions:
    - Suggested `uid,cn,ou` for VLV sorting instead of only `uid`.
    - Offered both `none` and `openldap` as lockout strategy choices.
    - Added an example placeholder member DN, `cn=dummy,o=whatever`, for customization.
- Updated the connector parent from `1.5.3.0-M3` to `1.5.3.0`.
- Updated Apache MINA to `2.2.9`, Apache Commons Lang to `3.20.0`, and the test dependency Apache Commons IO to `2.22.0`.

### Fixed

- Fixed handling of Active Directory security descriptor attributes, such as `msDS-GroupMSAMembership`, by treating their syntax as binary instead of decoding values as UTF-8 strings.
- Fixed recognition of Active Directory object classes extending `user` by checking superior object classes recursively, allowing user-specific schema and operation handling to apply to derived classes.
- Fixed translation of attribute existence and absence filters to LDAP presence assertions, using `(attribute=*)` and `(!(attribute=*))`, respectively.
- Added recognition of Active Directory `X_BIND_REQUIRED` error code `DSID-0C090D5C`, mapping it to `ReconnectException` consistently with previously supported DSIDs.