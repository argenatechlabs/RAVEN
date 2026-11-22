"use client";

import { useState } from "react";
import { api, type ActiveChecksInput } from "@/lib/api";
import type { ActiveChecksResult } from "@/lib/types";

function parseFields(text: string): Record<string, string> {
  const value: unknown = JSON.parse(text || "{}");
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.values(value).some((v) => typeof v !== "string")) {
    throw new Error("Form alanları JSON nesnesi ve değerler metin olmalı.");
  }
  return value as Record<string, string>;
}

export function ActiveChecks({ id, results, onCompleted }: {
  id: string; results?: ActiveChecksResult; onCompleted: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [csrfUrl, setCsrfUrl] = useState("");
  const [csrfFields, setCsrfFields] = useState("{}");
  const [csrfToken, setCsrfToken] = useState("csrf_token");
  const [uploadUrl, setUploadUrl] = useState("");
  const [uploadFields, setUploadFields] = useState("{}");
  const [uploadField, setUploadField] = useState("file");
  const [ssrfUrl, setSsrfUrl] = useState("");
  const [ssrfParameter, setSsrfParameter] = useState("url");
  const [businessUrl, setBusinessUrl] = useState("");
  const [businessFields, setBusinessFields] = useState("{}");
  const [businessParameter, setBusinessParameter] = useState("amount");
  const [baseline, setBaseline] = useState("1");
  const [variant, setVariant] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [current, setCurrent] = useState<ActiveChecksResult | undefined>();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!authorized) { setError("Ayrı aktif test onayı gerekli."); return; }
    try {
      const data: ActiveChecksInput = { authorized_active: true };
      if (csrfUrl) data.csrf = { url: csrfUrl.trim(), fields: parseFields(csrfFields), token_field: csrfToken.trim() };
      if (uploadUrl) data.upload = { url: uploadUrl.trim(), fields: parseFields(uploadFields), file_field: uploadField.trim() };
      if (ssrfUrl) data.ssrf = { url: ssrfUrl.trim(), parameter: ssrfParameter.trim() };
      if (businessUrl) data.business = { url: businessUrl.trim(), fields: parseFields(businessFields), parameter: businessParameter.trim(), baseline, variant };
      if (!data.csrf && !data.upload && !data.ssrf && !data.business) throw new Error("En az bir test URL'si girin.");
      setBusy(true);
      const response = await api.runActiveChecks(id, data);
      setCurrent(response);
      // Do not keep submitted credentials/tokens in component state.
      setCsrfFields("{}"); setUploadFields("{}"); setBusinessFields("{}");
      setAuthorized(false);
      onCompleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Aktif test başarısız.");
    } finally { setBusy(false); }
  }

  const displayed = current || results;
  const input = "input-neon mt-1 w-full text-xs";
  return <section className="panel space-y-3 p-4">
    <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="label-neon">Aktif doğrulama · sadece izinli test ortamı</h2><button type="button" onClick={() => setOpen(!open)} className="btn-ghost text-xs">{open ? "Kapat" : "Testleri yapılandır"}</button></div>
    <p className="text-xs text-yellow-300">POST işlemleri ve yükleme gerçek veri oluşturabilir veya değiştirebilir. Yalnızca güvenli, geri alınabilir test endpointleri ve test hesabı kullanın. Dosya sunucuda kalabilir. Bulunan formlar otomatik gönderilmez.</p>
    {open && <form onSubmit={submit} autoComplete="off" className="space-y-4 text-xs">
      <p className="text-muted">Sadece doldurulan testler çalışır; URL taranan host ve portla aynı olmalıdır. Form alanları JSON olarak gönderilir ve sonuçlara kaydedilmez. Kimlik doğrulama için sunucu tarafındaki SCAN_HEADERS/SCAN_COOKIE kullanılır.</p>
      <fieldset className="space-y-2 rounded border border-line p-3"><legend className="text-neon">CSRF · iki POST</legend>
        <input className={input} placeholder="Test formunun POST URL'si" value={csrfUrl} onChange={e => setCsrfUrl(e.target.value)} />
        <input className={input} placeholder="Token alan adı" value={csrfToken} onChange={e => setCsrfToken(e.target.value)} />
        <input className={input} placeholder={'Alanlar: {"csrf_token":"test"}'} value={csrfFields} onChange={e => setCsrfFields(e.target.value)} />
      </fieldset>
      <fieldset className="space-y-2 rounded border border-line p-3"><legend className="text-neon">Dosya yükleme · zararsız TXT</legend>
        <input className={input} placeholder="Test yükleme URL'si" value={uploadUrl} onChange={e => setUploadUrl(e.target.value)} />
        <input className={input} placeholder="Dosya alan adı" value={uploadField} onChange={e => setUploadField(e.target.value)} />
        <input className={input} placeholder="Diğer alanlar: {}" value={uploadFields} onChange={e => setUploadFields(e.target.value)} />
      </fieldset>
      <fieldset className="space-y-2 rounded border border-line p-3"><legend className="text-neon">SSRF · kontrollü geri çağrı</legend>
        <input className={input} placeholder="URL parametresi alan GET endpointi" value={ssrfUrl} onChange={e => setSsrfUrl(e.target.value)} />
        <input className={input} placeholder="Parametre adı" value={ssrfParameter} onChange={e => setSsrfParameter(e.target.value)} />
        <p className="text-muted">Backend için OAST_PUBLIC_URL yapılandırılmış ve hedef tarafından erişilebilir olmalıdır.</p>
      </fieldset>
      <fieldset className="space-y-2 rounded border border-line p-3"><legend className="text-neon">İş mantığı · iki POST</legend>
        <input className={input} placeholder="Test endpointi URL'si" value={businessUrl} onChange={e => setBusinessUrl(e.target.value)} />
        <input className={input} placeholder="Karşılaştırılacak parametre" value={businessParameter} onChange={e => setBusinessParameter(e.target.value)} />
        <div className="grid grid-cols-2 gap-2"><input className={input} placeholder="Normal değer" value={baseline} onChange={e => setBaseline(e.target.value)} /><input className={input} placeholder="Test değeri" value={variant} onChange={e => setVariant(e.target.value)} /></div>
        <input className={input} placeholder="Diğer alanlar: {}" value={businessFields} onChange={e => setBusinessFields(e.target.value)} />
      </fieldset>
      <label className="flex items-start gap-2 text-yellow-300"><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="mt-0.5 accent-[#00ff41]" />Bu endpointlerde POST ve zararsız test dosyası göndermeye yetkiliyim; olası durum değişikliği ve test artıklarını kabul ediyorum.</label>
      <button className="btn-neon text-xs" disabled={busy} type="submit">{busy ? "Test ediliyor…" : "Seçilen aktif testleri çalıştır"}</button>
      {error && <p className="text-red-400">{error}</p>}
    </form>}
    {displayed && <div className="space-y-2 text-xs"><p className="text-muted">Son aktif test · {displayed.timestamp}</p>{displayed.items.map((item, i) => <div key={i} className="rounded border border-line bg-black/40 p-2"><p className="break-all text-neon-dim">{item.category} · {item.url} · {item.status}</p><p className="mt-1 text-zinc-300">{item.detail}</p><p className="mt-1 text-muted">{item.baseline_status != null ? `Normal: HTTP ${item.baseline_status} · ` : ""}{item.test_status != null ? `Test: HTTP ${item.test_status}` : "Yanıt alınamadı veya durum mevcut değil"}</p></div>)}</div>}
  </section>;
}
