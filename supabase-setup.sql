-- ================================================================
-- 失控的生日研究所：Supabase 一鍵設定（純 SQL 版，不需要 Edge Function）
-- 用法：Supabase 後台 → SQL Editor → New query → 全部貼上 → Run
-- 可重複執行；已存在的遊戲進度不會被清掉。
-- ================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1. 資料表 -------------------------------------------------------
create table if not exists public.pbe_state (
  id int primary key default 1 check (id = 1),
  state jsonb not null,
  version bigint not null default 1,
  updated_at timestamptz not null default now()
);
create table if not exists public.pbe_secrets (
  id int primary key default 1 check (id = 1),
  secrets jsonb not null default '{}'::jsonb,
  password_hash text
);

alter table public.pbe_state enable row level security;
alter table public.pbe_secrets enable row level security;

-- 所有人可以讀遊戲進度（即時同步用）；寫入一律透過下方函式
drop policy if exists "pbe read state" on public.pbe_state;
create policy "pbe read state" on public.pbe_state for select to anon, authenticated using (true);
-- pbe_secrets 不設任何 policy：玩家完全讀不到生日、通關碼

-- 2. 即時同步 -----------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_publication_tables
                 where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'pbe_state') then
    alter publication supabase_realtime add table public.pbe_state;
  end if;
end $$;

-- 3. 函式 ---------------------------------------------------------
-- 讀取目前狀態＋伺服器時間
create or replace function public.pbe_get()
returns jsonb language sql security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'state', (select state from pbe_state where id = 1),
    'version', coalesce((select version from pbe_state where id = 1), 0),
    'now', floor(extract(epoch from clock_timestamp()) * 1000),
    'has_password', exists (select 1 from pbe_secrets where id = 1 and password_hash is not null)
  );
$$;

-- 玩家儲存狀態（樂觀鎖：版本不符回傳 -1，前端會自動重試）
create or replace function public.pbe_save(p_state jsonb, p_version bigint)
returns bigint language plpgsql security definer set search_path = public, extensions as $$
declare v bigint;
begin
  if octet_length(p_state::text) > 1500000 then raise exception 'state too large'; end if;
  if p_version = 0 then
    insert into pbe_state (id, state, version) values (1, p_state, 1) on conflict (id) do nothing;
    return case when found then 1 else -1 end;
  end if;
  update pbe_state set state = p_state, version = version + 1, updated_at = now()
   where id = 1 and version = p_version returning version into v;
  return coalesce(v, -1);
end $$;

-- 第一次設定主持人密碼（已設定過就不能再用這個函式）
create or replace function public.pbe_setup_password(p_password text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(coalesce(p_password, '')) < 4 then return false; end if;
  insert into pbe_secrets (id) values (1) on conflict (id) do nothing;
  update pbe_secrets set password_hash = crypt(p_password, gen_salt('bf'))
   where id = 1 and password_hash is null;
  return found;
end $$;

create or replace function public.pbe_check_password(p_password text)
returns boolean language sql security definer set search_path = public, extensions as $$
  select coalesce((select password_hash = crypt(coalesce(p_password, ''), password_hash)
                     from pbe_secrets where id = 1 and password_hash is not null), false);
$$;

-- 主持人讀取秘密資料
create or replace function public.pbe_host_get(p_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if not pbe_check_password(p_password) then raise exception 'wrong password'; end if;
  return coalesce((select secrets from pbe_secrets where id = 1), '{}'::jsonb);
end $$;

-- 主持人儲存狀態＋秘密資料
create or replace function public.pbe_host_save(p_password text, p_state jsonb, p_secrets jsonb, p_version bigint)
returns bigint language plpgsql security definer set search_path = public, extensions as $$
declare v bigint;
begin
  if not pbe_check_password(p_password) then raise exception 'wrong password'; end if;
  v := pbe_save(p_state, p_version);
  if v > 0 then
    update pbe_secrets set secrets = p_secrets where id = 1;
  end if;
  return v;
end $$;

-- 主持人變更密碼
create or replace function public.pbe_change_password(p_old text, p_new text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  if not pbe_check_password(p_old) or length(coalesce(p_new, '')) < 4 then return false; end if;
  update pbe_secrets set password_hash = crypt(p_new, gen_salt('bf')) where id = 1;
  return true;
end $$;

-- 玩家答案核對（不會洩漏正確答案）
-- kind = 'birthday'：a = 被問的玩家 id、b = 月、c = 日
-- kind = 'safe'    ：a = 保險箱密碼
-- kind = 'ghost'   ：a = 通關碼（尚未設定時回傳 null）
create or replace function public.pbe_check(kind text, a text, b int default null, c int default null)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare s jsonb := coalesce((select secrets from pbe_secrets where id = 1), '{}'::jsonb);
        total int;
begin
  if kind = 'birthday' then
    return (s->'birthdays'->a->>'m')::int = b and (s->'birthdays'->a->>'d')::int = c;
  elsif kind = 'safe' then
    select coalesce(sum((value->>'d')::int), 0) into total from jsonb_each(coalesce(s->'birthdays', '{}'::jsonb));
    return trim(coalesce(a, '')) = total::text;
  elsif kind = 'ghost' then
    if coalesce(s->>'ghostCode', '') = '' then return null; end if;
    return upper(regexp_replace(coalesce(a, ''), '\s', '', 'g')) = upper(regexp_replace(s->>'ghostCode', '\s', '', 'g'));
  end if;
  return false;
end $$;

-- 只開放上面的函式給網頁呼叫
revoke all on function public.pbe_get(), public.pbe_save(jsonb, bigint), public.pbe_setup_password(text),
  public.pbe_check_password(text), public.pbe_host_get(text), public.pbe_host_save(text, jsonb, jsonb, bigint),
  public.pbe_change_password(text, text), public.pbe_check(text, text, int, int) from public;
grant execute on function public.pbe_get(), public.pbe_save(jsonb, bigint), public.pbe_setup_password(text),
  public.pbe_check_password(text), public.pbe_host_get(text), public.pbe_host_save(text, jsonb, jsonb, bigint),
  public.pbe_change_password(text, text), public.pbe_check(text, text, int, int) to anon, authenticated;

-- 4. 照片儲存空間 -------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('pbe-photos', 'pbe-photos', true, 8388608, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set public = true, file_size_limit = 8388608,
  allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp'];

drop policy if exists "pbe photos read" on storage.objects;
drop policy if exists "pbe photos upload" on storage.objects;
drop policy if exists "pbe photos delete" on storage.objects;
create policy "pbe photos read" on storage.objects for select to anon, authenticated using (bucket_id = 'pbe-photos');
create policy "pbe photos upload" on storage.objects for insert to anon, authenticated with check (bucket_id = 'pbe-photos');
create policy "pbe photos delete" on storage.objects for delete to anon, authenticated using (bucket_id = 'pbe-photos');

-- 完成！看到 Success 就可以回去告訴 Claude 了。
