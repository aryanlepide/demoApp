create table if not exists public.scan_records (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  file_name text not null check (char_length(file_name) between 1 and 255),
  scanned_at timestamptz not null default now(),
  risk text not null check (risk in ('None', 'Low', 'Medium', 'High', 'Critical')),
  finding_count integer not null default 0 check (finding_count >= 0),
  findings jsonb not null default '[]'::jsonb check (jsonb_typeof(findings) = 'array')
);

create index if not exists scan_records_user_scanned_at_idx
  on public.scan_records (user_id, scanned_at desc);

alter table public.scan_records enable row level security;

grant select, insert, delete on public.scan_records to authenticated;

drop policy if exists "Users can read their own scans" on public.scan_records;
create policy "Users can read their own scans"
  on public.scan_records for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can insert their own scans" on public.scan_records;
create policy "Users can insert their own scans"
  on public.scan_records for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can delete their own scans" on public.scan_records;
create policy "Users can delete their own scans"
  on public.scan_records for delete to authenticated
  using ((select auth.uid()) = user_id);

comment on table public.scan_records is
  'Stores only scan metadata and masked aggregated findings; never raw file contents or unmasked matches.';