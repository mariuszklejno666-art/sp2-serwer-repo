# Machine account recovery

This path applies only to an authenticated, browser-approved device UUID with MAC
matching registered inventory, local PartOfDomain=True in the configured domain,
secure_channel=False, confirmed missing source account and a conflict-free target.
Unknown secure channel, LDAP/DNS errors, invalid OU, another agent, existing target
account or DNS/SPN conflict block the plan. No unjoin or manual computer creation.

`MACHINE_ACCOUNT_RECOVERY_ENABLED=false` is the default. Enable only after the
isolated Windows/Samba integration acceptance below. A passing mocked test suite
does not establish Kerberos compatibility for the actual Windows/Samba versions.

The existing DomainRecovery unique reservations bind agent, approved UUID, MAC,
inventory IP addresses, exact target name/OU and request ID. Both existing
name-preview endpoints include active recovery reservations in name availability.
Repeated request IDs return the same plan; other requests cannot reserve its name.
Recovery does not reuse enrollment credentials to expose the service password.

The client uses the existing automatic browser authorization when UUID approval is
missing. A registered MAC/IP inventory is required; it is not silently invented
from the request. Confirm local administrator login before executing recovery.

## Join and reconciliation

1. Recheck AD, UUID/MAC, domain and boot ID, then commit `begin` with optimistic
   version checking. Install the existing resume task and persist nonsecret state.
2. The new plan-scoped credential endpoint rechecks identity/conflicts, allows one
   delivery within five minutes on the same boot, commits `credential_issued`, and
   returns configured service credentials with Cache-Control: no-store. A lost
   response is an uncertain outcome, never a reason to deliver or join again.
3. Use documented SetComputerNameEx and local NetJoinDomain with JOIN_DOMAIN,
   ACCT_CREATE, DOMAIN_JOIN_IF_JOINED, JOIN_WITH_NEW_NAME and NO_ACCT_REUSE.
   Account creation and the machine secret are established by join itself.
   No Remove-Computer, force-unjoin, direct registry edits, account reuse,
   unsecured join, or NTLM policy changes. Password buffers are cleared and the
   PSCredential is disposed; JSON/state/crash logs never store the service secret.
4. Restart and observe. A healthy secure channel on a different boot, issued join,
   target account SID/enabled state, exact OU, matching DNS hostname, resolved
   inventory IP addresses and both HOST SPNs are required to complete. Pin the
   observed target SID in the durable plan. Another SID requires manual review.
5. Exceptions, failure reports, incomplete metadata or changed membership preserve
   the reservation and require review. Observe after failure can still recognize
   a successful join; it cannot automatically repeat an uncertain operation.
   Staged local naming may survive an API failure; do not blindly roll it back.

The supported APIs are described at
https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netjoindomain
and https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-setcomputernameexw.

## Acceptance before production enablement

Use an isolated Windows clone and isolated Samba domain with the intended versions
and NTLM disabled. Take snapshots. Reproduce missing machine account while Windows
remains joined; approve UUID and register MAC/IP. Reserve S11-15 in Sala11. Verify
one join, no account reuse/unjoin and no policy changes. Verify authentication
uses Kerberos in DC/Windows audit evidence. Test lost credential response, process
kill before/after native join, restart, SID replacement, target collision, LDAP
failure and bad OU/DNS/SPNs. Confirm neither secrets nor service passwords appear
in state, files, package, process arguments or crash logs. Restore snapshots between
cases. Record versions, commit, checks and results before enabling the feature.

## Controlled SP2 ADMIN deployment

Before changing production, obtain authenticated administrative SSH access, locate
the actual service WorkingDirectory, EnvironmentFile and database, and record
running commit and health. Do not print EnvironmentFile contents or secrets.
Run full Linux pytest/ruff and Windows build/self-tests at the exact PR head;
check CI before merging/deploying with the feature disabled. Complete integration
acceptance above before enabling recovery or issuing a production recovery begin.

Back up current release, configuration with restrictive permissions, and database
using its consistent backup mechanism. Verify the backup and record rollback
paths. Deploy the merged commit through the installed service's established method;
keep recovery disabled initially. Startup creates additive recovery identity tables,
including unique UUID/MAC claims; existing columns and agent tokens are preserved.
Check existing hardware records for duplicate UUID/MAC values before deployment.
Restart only SP2 ADMIN, then verify systemd active, /health, recovery capabilities,
ordinary authentication and error logs. On failure restore the previous release
and configuration; restore database only if required by verified migration state.
Restart SP2 ADMIN and repeat health checks. Never restart Samba or mutate AD as
part of deployment. Enable recovery only after acceptance and state verification.

For S11-10, the next safe step is read-only inventory/diagnosis and confirmation of
approved UUID/MAC/IP, local administrator access, missing S11-10$ and absent S11-15$
plus target OU/DNS/SPN availability. Do not issue a recovery begin before acceptance.
