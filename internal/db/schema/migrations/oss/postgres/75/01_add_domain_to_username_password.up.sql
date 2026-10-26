-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  -- Add domain and domain_hmac columns to credential_static_username_password_credential
  -- for RDP credential injection support.
  alter table credential_static_username_password_credential
    add column if not exists domain text,
    add column if not exists domain_hmac bytea;

commit;
