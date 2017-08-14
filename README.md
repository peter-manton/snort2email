# snort2email

A script that polls snort data exported with barnyard2 from PostgreSQL.

Usage: snort2email.sh <database> <alert-threshold> <alert-email> <priority-threshold>

Version 1.1: Prevented multiple alerts from the same stream and added signature priority to subject field.
Version 1.0: Initial release.
