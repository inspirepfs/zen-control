# ZEN Control RouterOS Integration

This directory contains **public, credential-free RouterOS inspection/verification helpers** and the documented authority assumptions used by ZEN.

The v0.53.1 repository intentionally does not ship a blind "configure my firewall" script. Critical RouterOS rules are manually owned and ZEN's safety model depends on operators understanding that boundary. Future bootstrap scripts should be parameterized, idempotent and separately reviewable.

## Start read-only

Upload/paste the commands in `inspect.rsc` to capture the router areas ZEN depends on. `verify.rsc` narrows the output to the principal ZEN authority namespaces.

Both files are read-only: they contain `print`/`:put` commands only and do not add, set, move, remove, enable or disable configuration.

## Core concepts

ZEN expects a dedicated restricted-policy path with:

- `Restricted_Devices` as the managed-device address list;
- a restricted-web firewall chain and one `RW99 - Return` authority anchor;
- the QUIC/HTTP3 restriction expected by the application;
- deterministic app-owned `MC_*` / `MC|SVC|*` resources for approved custom services;
- FastTrack disabled for, or explicitly excluding, restricted devices;
- static DHCP identity for devices participating in controlled Kid Control migration.

Exact validation remains in the application. Do not "repair" a router simply by copying example output from documentation.

## API account

Use a dedicated RouterOS API account with only the permissions your deployment requires. Never store its password in `.rsc` files; put it in the host `.env` file, which is intentionally ignored by Git.

## Kid Control

During migration:

- `/ip/kid-control` and `/ip/kid-control/device` are read as legacy source evidence;
- `/ip/kid-control/device` remains write-forbidden;
- the only bounded legacy authority mutation is the exact validated profile `disabled` flag during cutover/rollback;
- legacy schedules/device membership are retained for rollback.
