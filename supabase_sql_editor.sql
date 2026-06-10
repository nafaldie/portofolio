-- =========================================================
-- SQL EDITOR SUPABASE - PORTFOLIO ADMIN EDIT
-- Tinggal copy-paste semua SQL ini ke Supabase SQL Editor lalu RUN.
-- Default passcode admin: NafaPorto2026!
-- Setelah website deploy, buka admin dengan klik foto berdiri 5x.
-- =========================================================

begin;

create extension if not exists pgcrypto;

create table if not exists public.portfolio_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.portfolio_admin_secrets (
  id boolean primary key default true,
  passcode_hash text not null,
  updated_at timestamptz not null default now(),
  constraint portfolio_admin_secrets_single_row check (id = true)
);

create table if not exists public.portfolio_admin_sessions (
  token uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index if not exists portfolio_admin_sessions_expires_idx
on public.portfolio_admin_sessions (expires_at);

insert into public.portfolio_settings (key, value)
values (
  'site_state',
  '{
    "version": 1,
    "texts": {},
    "images": {},
    "customCSS": "",
    "assetNotes": "",
    "cards": [],
    "sections": [],
    "updatedAt": null
  }'::jsonb
)
on conflict (key) do nothing;

-- Passcode default. Kalau SQL ini dijalankan ulang, passcode akan kembali menjadi NafaPorto2026!
insert into public.portfolio_admin_secrets (id, passcode_hash)
values (true, crypt('NafaPorto2026!', gen_salt('bf')))
on conflict (id) do update set
  passcode_hash = excluded.passcode_hash,
  updated_at = now();

alter table public.portfolio_settings enable row level security;
alter table public.portfolio_admin_secrets enable row level security;
alter table public.portfolio_admin_sessions enable row level security;

drop policy if exists portfolio_settings_public_read on public.portfolio_settings;
create policy portfolio_settings_public_read
on public.portfolio_settings
for select
to anon, authenticated
using (true);

-- Tidak ada policy write untuk anon/authenticated.
-- Write hanya lewat RPC security definer di bawah.

create or replace function public.portfolio_get_state()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select coalesce(
    (select value from public.portfolio_settings where key = 'site_state'),
    '{}'::jsonb
  );
$$;

create or replace function public.portfolio_admin_login(p_passcode text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_hash text;
  v_token uuid := gen_random_uuid();
begin
  select passcode_hash into v_hash
  from public.portfolio_admin_secrets
  where id = true;

  if v_hash is null or crypt(coalesce(p_passcode, ''), v_hash) <> v_hash then
    raise exception 'PASSCODE_SALAH';
  end if;

  delete from public.portfolio_admin_sessions
  where expires_at < now();

  insert into public.portfolio_admin_sessions (token, expires_at)
  values (v_token, now() + interval '8 hours');

  return v_token;
end;
$$;

create or replace function public.portfolio_session_is_valid(p_token uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.portfolio_admin_sessions
    where token = p_token
      and expires_at > now()
  );
$$;

create or replace function public.portfolio_save_state(p_token uuid, p_state jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.portfolio_session_is_valid(p_token) then
    raise exception 'TOKEN_TIDAK_VALID_ATAU_EXPIRED';
  end if;

  if p_state is null or jsonb_typeof(p_state) <> 'object' then
    raise exception 'STATE_HARUS_JSON_OBJECT';
  end if;

  insert into public.portfolio_settings (key, value, updated_at)
  values ('site_state', p_state, now())
  on conflict (key) do update set
    value = excluded.value,
    updated_at = now();

  return p_state;
end;
$$;

create or replace function public.portfolio_admin_logout(p_token uuid)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.portfolio_admin_sessions
  where token = p_token;
  return true;
end;
$$;

create or replace function public.portfolio_admin_change_passcode(p_token uuid, p_new_passcode text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.portfolio_session_is_valid(p_token) then
    raise exception 'TOKEN_TIDAK_VALID_ATAU_EXPIRED';
  end if;

  if length(coalesce(p_new_passcode, '')) < 8 then
    raise exception 'PASSCODE_MINIMAL_8_KARAKTER';
  end if;

  update public.portfolio_admin_secrets
  set passcode_hash = crypt(p_new_passcode, gen_salt('bf')),
      updated_at = now()
  where id = true;

  return true;
end;
$$;

revoke all on table public.portfolio_admin_secrets from anon, authenticated;
revoke all on table public.portfolio_admin_sessions from anon, authenticated;

grant usage on schema public to anon, authenticated;
grant select on table public.portfolio_settings to anon, authenticated;
grant execute on function public.portfolio_get_state() to anon, authenticated;
grant execute on function public.portfolio_admin_login(text) to anon, authenticated;
grant execute on function public.portfolio_save_state(uuid, jsonb) to anon, authenticated;
grant execute on function public.portfolio_admin_logout(uuid) to anon, authenticated;
grant execute on function public.portfolio_admin_change_passcode(uuid, text) to anon, authenticated;

commit;
