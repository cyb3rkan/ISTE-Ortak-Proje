/**
 * Demo yönetici kullanıcı yönetimi ekranı.
 *
 * Yalnızca `RequireDemoAdmin` arkasında render edilir. Listeyi ve durum
 * değişikliklerini yalnızca `useDemoAdminUsers().service` üzerinden yapar;
 * fixture'lara doğrudan dokunmaz. API anahtarı, sağlayıcı, analiz veya rapor
 * verisi ne istenir ne gösterilir. Rol atama ve hesap silme yoktur.
 */

import { useCallback, useEffect, useMemo, useState } from "react";

import { EmptyState } from "@/components/common/EmptyState";
import { LoadingState } from "@/components/common/LoadingState";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DEMO_ALERT } from "../components/DemoAuthCard";
import type {
  AdminUserScenarios,
  DemoAccountStatus,
  DemoManagedUser,
} from "../demoAdminService";
import { DEMO_ROLE_LABELS } from "../demoTypes";
import { useDemoAdminUsers } from "../useDemoAdminUsers";

type StatusFilter = "all" | DemoAccountStatus;

interface PendingChange {
  user: DemoManagedUser;
  next: DemoAccountStatus;
}

const CONTROL =
  "mt-1 w-full rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-accent";

const PILL = "inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium";

export function DemoAdminUsersPage() {
  const { service } = useDemoAdminUsers();

  const [users, setUsers] = useState<DemoManagedUser[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [pending, setPending] = useState<PendingChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [resultMessage, setResultMessage] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!service) return;
    setUsers(null);
    setLoadError(false);
    try {
      const result = await service.listUsers();
      if (result.ok) setUsers(result.users);
      else setLoadError(true);
    } catch {
      setLoadError(true);
    }
  }, [service]);

  useEffect(() => {
    void load();
  }, [load]);

  const visibleUsers = useMemo(() => {
    if (!users) return [];
    const q = query.trim().toLocaleLowerCase("tr-TR");
    return users.filter(
      (u) =>
        (statusFilter === "all" || u.accountStatus === statusFilter) &&
        (!q ||
          u.displayName.toLocaleLowerCase("tr-TR").includes(q) ||
          u.demoEmail.toLocaleLowerCase("tr-TR").includes(q)),
    );
  }, [users, query, statusFilter]);

  if (!service) return null;

  async function confirmChange() {
    if (!pending || !service) return;
    setBusy(true);
    setResultMessage("");
    setActionError(null);
    const { user, next } = pending;
    try {
      const result = await service.setAccountStatus(user.id, next);
      if (result.ok) {
        setUsers((prev) => prev?.map((u) => (u.id === result.user.id ? result.user : u)) ?? prev);
        setResultMessage(
          next === "disabled"
            ? `Demo: ${user.displayName} hesabı devre dışı bırakıldı (yalnızca demo belleğinde).`
            : `Demo: ${user.displayName} hesabı etkinleştirildi (yalnızca demo belleğinde).`,
        );
      } else if (result.error === "self_action_forbidden") {
        setActionError("Kendi hesabınızın durumunu değiştiremezsiniz.");
      } else if (result.error === "admin_protected") {
        setActionError("Yönetici hesabının durumu bu ekrandan değiştirilemez.");
      } else {
        setActionError("Hesap durumu değiştirilemedi (demo senaryosu). Lütfen tekrar deneyin.");
      }
    } catch {
      setActionError("Hesap durumu değiştirilemedi. Lütfen tekrar deneyin.");
    }
    setBusy(false);
    setPending(null);
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Kullanıcı yönetimi</h1>
          <p className="mt-1 text-sm text-slate-400">
            Demo prototipi: Bu ekran gerçek hesapları yönetmez. Liste sahte demo verisinden
            oluşur; değişiklikler yalnızca bu sekmenin belleğinde tutulur ve sayfa
            yenilendiğinde sıfırlanır.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load()}
          className="min-h-10 shrink-0 rounded-md border border-surface-border bg-surface px-3 py-2 text-xs font-medium text-slate-200 hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent"
        >
          Listeyi yenile
        </button>
      </div>

      <div className="space-y-1 rounded-lg border border-surface-border bg-surface-raised px-4 py-3 text-xs text-slate-300">
        <p>
          Bu ekrandaki rol kontrolü yalnızca arayüzdedir ve gerçek güvenlik sağlamaz; gerçek
          sistemde yetkilendirme backend tarafından uygulanmalıdır.
        </p>
        <p className="text-slate-400">
          Yönetici yalnızca hesap durumunu görür; kullanıcıların sağlayıcı anahtarlarını,
          analizlerini veya raporlarını göremez. Rol atama ve hesap silme bu prototipte
          yoktur; sistemde tek yönetici olduğu varsayılır.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
        <div>
          <label htmlFor="admin-user-search" className="text-xs font-medium text-slate-400">
            Kullanıcı ara
          </label>
          <input
            id="admin-user-search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ad veya demo e-posta"
            className={CONTROL}
          />
        </div>
        <div>
          <label htmlFor="admin-user-status" className="text-xs font-medium text-slate-400">
            Hesap durumu
          </label>
          <select
            id="admin-user-status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            className={CONTROL}
          >
            <option value="all">Tümü</option>
            <option value="active">Etkin</option>
            <option value="disabled">Pasif</option>
          </select>
        </div>
      </div>

      <p role="status" aria-label="İşlem sonucu" className="text-xs text-slate-300">
        {resultMessage}
      </p>
      {actionError ? (
        <p role="alert" className={DEMO_ALERT}>
          {actionError}
        </p>
      ) : null}

      {!users && !loadError ? <LoadingState label="Demo kullanıcıları yükleniyor…" /> : null}

      {loadError ? (
        <div role="alert" className={DEMO_ALERT}>
          Demo kullanıcı listesi yüklenemedi.{" "}
          <button type="button" onClick={() => void load()} className="underline">
            Tekrar dene
          </button>
        </div>
      ) : null}

      {users && users.length === 0 ? (
        <EmptyState title="Gösterilecek demo kullanıcısı yok." />
      ) : null}

      {users && users.length > 0 ? (
        <>
          <p className="text-xs text-slate-500">
            {visibleUsers.length} / {users.length} demo kullanıcısı gösteriliyor
          </p>
          {visibleUsers.length === 0 ? (
            <EmptyState title="Aramanızla eşleşen demo kullanıcısı yok." />
          ) : (
            <ul aria-label="Demo kullanıcıları" className="grid gap-3 md:grid-cols-2">
              {visibleUsers.map((user) => (
                <UserItem
                  key={user.id}
                  user={user}
                  disabled={busy}
                  onRequestChange={(next) => {
                    setResultMessage("");
                    setActionError(null);
                    setPending({ user, next });
                  }}
                />
              ))}
            </ul>
          )}
        </>
      ) : null}

      <AdminDevPanel />

      <ConfirmDialog
        open={pending !== null}
        title={
          pending
            ? pending.next === "disabled"
              ? `${pending.user.displayName} hesabı devre dışı bırakılsın mı?`
              : `${pending.user.displayName} hesabı etkinleştirilsin mi?`
            : ""
        }
        confirmLabel={pending?.next === "disabled" ? "Devre dışı bırak" : "Etkinleştir"}
        busyLabel="İşleniyor…"
        tone={pending?.next === "disabled" ? "danger" : "primary"}
        busy={busy}
        onConfirm={() => void confirmChange()}
        onCancel={() => setPending(null)}
      >
        Bu işlem yalnızca demo belleğindeki sahte kaydın durumunu “
        {pending?.next === "disabled" ? "Pasif" : "Etkin"}” yapar. Gerçek bir hesap
        değişmez; hesap silinmez ve e-posta gönderilmez.
      </ConfirmDialog>
    </div>
  );
}

interface UserItemProps {
  user: DemoManagedUser;
  disabled: boolean;
  onRequestChange: (next: DemoAccountStatus) => void;
}

function UserItem({ user, disabled, onRequestChange }: UserItemProps) {
  const active = user.accountStatus === "active";
  const canChange = !user.isSelf && user.role !== "admin";

  return (
    <li className="flex flex-col gap-3 rounded-lg border border-surface-border bg-surface-raised p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-slate-100">
            {user.displayName}
            {user.isSelf ? <span className="ml-1 font-normal text-slate-400">(siz)</span> : null}
          </h2>
          <p className="break-all font-mono text-xs text-slate-400">{user.demoEmail}</p>
        </div>
        <span className={`${PILL} border-slate-500/40 bg-slate-500/15 text-slate-300`}>
          {DEMO_ROLE_LABELS[user.role]}
        </span>
      </div>

      <dl className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <dt className="text-slate-500">Hesap durumu</dt>
          <dd className="mt-0.5">
            <span
              className={`${PILL} ${
                active
                  ? "border-risk-low/40 bg-risk-low/15 text-risk-low"
                  : "border-risk-critical/40 bg-risk-critical/15 text-risk-critical"
              }`}
            >
              {active ? "Etkin" : "Pasif"}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">E-posta doğrulama</dt>
          <dd className="mt-0.5 text-slate-300">
            {user.emailVerification === "verified" ? "Doğrulandı" : "Doğrulama bekliyor"}
          </dd>
        </div>
      </dl>

      <div className="mt-auto border-t border-surface-border pt-3">
        {canChange ? (
          <button
            type="button"
            disabled={disabled}
            onClick={() => onRequestChange(active ? "disabled" : "active")}
            aria-label={`${user.displayName} hesabını ${active ? "devre dışı bırak" : "etkinleştir"}`}
            className={`min-h-10 rounded-md border px-3 py-2 text-xs font-medium focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-60 ${
              active
                ? "border-risk-critical/50 text-risk-critical hover:bg-risk-critical/10"
                : "border-surface-border text-slate-200 hover:border-accent/50"
            }`}
          >
            {active ? "Devre dışı bırak" : "Etkinleştir"}
          </button>
        ) : (
          <p className="text-xs text-slate-500">
            {user.isSelf
              ? "Kendi hesabınızı devre dışı bırakamazsınız."
              : "Yönetici hesabının durumu bu ekrandan değiştirilemez."}
          </p>
        )}
      </div>
    </li>
  );
}

const LIST_OPTIONS: { value: AdminUserScenarios["list"]; label: string }[] = [
  { value: "success", label: "Demo liste" },
  { value: "empty", label: "Boş liste" },
  { value: "error", label: "Yükleme hatası" },
];

const UPDATE_OPTIONS: { value: AdminUserScenarios["update"]; label: string }[] = [
  { value: "success", label: "Demo başarı" },
  { value: "error", label: "Beklenmeyen hata" },
];

/** Geliştirici demo paneli: yalnızca mock sonucu seçer, ağ veya kalıcı kayıt yoktur. */
function AdminDevPanel() {
  const { scenarios, setScenario } = useDemoAdminUsers();
  return (
    <fieldset className="rounded-lg border border-dashed border-slate-600 px-4 pb-4 pt-2">
      <legend className="px-1 font-mono text-[11px] font-semibold uppercase tracking-wide text-slate-400">
        Geliştirici demo paneli
      </legend>
      <p className="text-xs text-slate-400">
        Yalnızca prototipteki durumları denemek içindir; gerçek uygulamada bulunmaz. Liste
        seçimi “Listeyi yenile” ile, durum seçimi bir sonraki onaylı işlemde uygulanır.
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="admin-scenario-list" className="text-xs font-medium text-slate-400">
            Liste yükleme sonucu
          </label>
          <select
            id="admin-scenario-list"
            value={scenarios.list}
            onChange={(e) => setScenario("list", e.target.value as AdminUserScenarios["list"])}
            className={CONTROL}
          >
            {LIST_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="admin-scenario-update" className="text-xs font-medium text-slate-400">
            Durum değişikliği sonucu
          </label>
          <select
            id="admin-scenario-update"
            value={scenarios.update}
            onChange={(e) =>
              setScenario("update", e.target.value as AdminUserScenarios["update"])
            }
            className={CONTROL}
          >
            {UPDATE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </fieldset>
  );
}
