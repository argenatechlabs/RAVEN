<p align="center">
  <img src="docs/demo.gif" alt="RAVEN demo" width="720" />
</p>

# RAVEN — Autonomous AI Pentester

<p align="center">
  <img src="https://img.shields.io/badge/status-MVP-00ff41?style=for-the-badge" alt="status" />
  <img src="https://img.shields.io/badge/python-3.11-00b32d?style=for-the-badge&logo=python" alt="python" />
  <img src="https://img.shields.io/badge/frontend-Next.js_15-00ff41?style=for-the-badge&logo=nextdotjs" alt="nextjs" />
  <img src="https://img.shields.io/badge/scanners-nuclei_9000%2B-00b32d?style=for-the-badge" alt="nuclei" />
  <img src="https://img.shields.io/badge/AI-OpenAI_%7C_Ollama-00ff41?style=for-the-badge" alt="ai" />
  <img src="https://img.shields.io/badge/license-MIT-6b7280?style=for-the-badge" alt="license" />
</p>

**Domain gir → 5 dakikada otomatik sızma testi → AI analizi → profesyonel PDF rapor.**

RAVEN, bug bounty hunter, KOBİ/startup, SOC ekipleri ve öğrenciler için tek tıkla
çalıştırılabilen, kendi kendine yeten bir güvenlik tarama platformudur.
subfinder + httpx + katana + nuclei binary'leri Docker imajına gömülüdür; tarayıcı
üzerinden hedef girersiniz, canlı loglar izlersiniz, bulguları AI analiziyle
okursunuz ve tek tıkla PDF/JSON rapor alırsınız.

<p align="center">
  <a href="https://raven.example.com"><strong>▶ Live Demo</strong></a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#ozellikler">Özellikler</a> ·
  <a href="#api">API</a> ·
  <a href="#yasal-uyari">Yasal Uyarı</a>
</p>

> **Not:** Bu depo bir MVP'dir. Continuous monitoring, SSO/RBAC, organizasyon
> yapısı, Slack/Jira entegrasyonu, HTML/Excel rapor gibi özellikler bilinçli olarak
> kapsam dışı bırakılmıştır.

---

## Hızlı Başlangıç (Quick Start)

Gereksinim: Docker + Docker Compose v2.

```bash
git clone https://github.com/argenatechlabs/RAVEN.git
cd RAVEN
cp .env.example .env          # opsiyonel: OpenAI anahtarınızı ekleyin
docker compose up --build
```

Tarayıcınızda açın:

| Servis | Adres |
| --- | --- |
| **Frontend (Dashboard)** | http://localhost:3000 |
| **Backend API** | http://localhost:8000 |
| **API Dokümantasyonu** | http://localhost:8000/docs |

İlk tarama için `testphp.vulnweb.com` gibi izinli bir hedefi kullanın, yasal onay
kutusunu işaretleyin ve **Tara** butonuna basın.

Docker imajı ilk kez build edilirken scanner binary'leri (subfinder, httpx, katana,
nuclei) ve nuclei şablonları indirilir; bu nedenle ilk build birkaç dakika sürer.

### Çevre değişkenleri

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `AI_PROVIDER` | `auto` | `auto` \| `openai` \| `anthropic` \| `gemini` \| `xai` \| `openrouter` \| `deepseek` \| `mistral` \| `groq` \| `ollama` \| `custom` \| `local` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | boş / `gpt-4o-mini` | OpenAI |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | boş / `claude-sonnet-4-5` | Claude |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | boş / `gemini-2.5-flash` | Gemini |
| `XAI_API_KEY` / `XAI_MODEL` | boş / `grok-3` | Grok |
| `OPENROUTER_API_KEY` | boş | OpenRouter (anahtarsız da sınırlı çalışır) |
| `DEEPSEEK_API_KEY` / `MISTRAL_API_KEY` / `GROQ_API_KEY` | boş | Diğer sağlayıcılar |
| `CUSTOM_API_KEY` / `CUSTOM_BASE_URL` | boş | Herhangi bir OpenAI uyumlu API |
| `OLLAMA_URL` / `OLLAMA_MODEL` | `http://ollama:11434` / `llama3.1` | Yerel Ollama |
| `DEMO_MODE` | `false` | Binary/hedef olmadan uçtan uca demo çalıştırır |
| `SCANNER_TIMEOUT` | `1200` | Tarayıcıları için maksimum süre (sn) |

### AI Sağlayıcıları

RAVEN, **istediğiniz her AI'yi** kullanmanızı sağlar: OpenAI, Anthropic Claude,
Google Gemini, xAI Grok, OpenRouter, DeepSeek, Mistral, Groq, yerel Ollama ve
herhangi bir OpenAI uyumlu API (`custom`).

- Ana sayfadaki **AI Sağlayıcı** dropdown'undan seçim yapın; **API Anahtarı /
  Model** butonuyla anahtarınızı ve modeli kaydedin.
- Anahtarlar veritabanında saklanır ve API yanıtlarında **asla** döndürülmez
  (yalnızca maskeli gösterilir: `gsk_••••abcd`).
- Seçim kalıcıdır; her tarama bu sağlayıcıyı kullanır. Tarama bazlı geçersiz
  kılmak için `POST /api/scans` içine `ai_provider` gönderin.
- Sağlayıcınız yanıt vermezse veya anahtar eksikse RAVEN otomatik olarak
  deterministik **yerel analiz** motoruna düşer; hiçbir bulgu analiz'siz
  kalmaz. Kullanılan sağlayıcı tarama sayfasında ve `meta.ai` içinde görünür.

```bash
curl http://localhost:8000/api/providers                 # saglayici listesi
curl -X PUT http://localhost:8000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"provider":"xai","api_key":"gsk_...","model":"grok-3"}'
```

---

## Özellikler

- **Tek tıkla tarama:** Domain + Tara. Önceden onay (checkbox) zorunludur.
- **Recon:** `subfinder` ile alt alan keşfi, `httpx` ile canlı kontrol, HTTP
  fingerprint ve teknoloji tespiti (`-tech-detect`).
- **Crawler:** `katana` ile endpoint ve JavaScript dosyası toplama.
- **Zafiyet taraması:** `nuclei` ile 9.000+ imza; `critical,high,medium` seviyesi
  varsayılandır, derin modda `low` dahildir.
- **Secret scan:** JS dosyalarında AWS, GitHub, GitLab, Slack, Google, Stripe,
  JWT, private key ve generic secret regex imzaları.
- **AI triage:** İstediğiniz sağlayıcıyı seçin (OpenAI, Claude, Gemini, Grok,
  OpenRouter, DeepSeek, Mistral, Groq, Ollama, özel) — false positive eleme,
  severity, CVSS, sömürü senaryosu, OWASP kategorisi ve fix kodu üretimi.
  Sağlayıcı yok/yanıt vermezse yerel analiz devreye girer.
- **Canlı ilerleme:** 2 saniyelik polling ile canlı log terminali, progress bar,
  risk skoru ve bulgu akışı.
- **Sonuçlar:** 0-100 risk skoru, severity filtresi, arama, false positive gösterimi,
  detay drawer'ı (AI analizi + kanıt + fix kodu).
- **Harita:** Subdomain ağacı görselleştirmesi (canlı/ölü, teknoloji rozetleri).
- **Rapor:** Tek tıkla PDF (reportlab) ve JSON export.
- **Geçmiş:** Tüm taramaların listesi, filtreleme ve "tekrar tara".
- **Hata yönetimi:** Tarayıcı binary'si yoksa yerleşik Python motoruna düşer,
  hatalar loglanır ve tarama tamamlanmamış olarak işaretlenir.

---

## Mimari

```
Kullanıcı (tarayıcı)
      │  domain + onay
      ▼
Next.js 15 (3000) ── /api/* proxy ──► FastAPI (8000)
                                          │  POST /api/scans
                                          ▼
                                      Redis kuyruğu
                                          │
                                          ▼
                              Worker (arka plan thread)
        recon → httpx → katana → nuclei → secrets → AI triage → PostgreSQL
                                          │
                                          ▼
                              Canlı log (DB + WebSocket) / Frontend polling
```

- **Backend:** Python 3.11, FastAPI, SQLAlchemy 2.0, Alembic (opsiyonel), Redis.
- **Veritabanı:** PostgreSQL 15 (`scans`, `findings`, `subdomains`, `scan_logs`).
- **Tarayıcılar:** Docker imajına gömülü binary'ler, `subprocess` ile çağrılır;
  hedefe saniyede en fazla 10 istek (`-rate-limit 10`).
- **Frontend:** Next.js 15 App Router, TypeScript, Tailwind CSS, Lucide Icons.
- **AI:** Kullanıcının seçtiği sağlayıcı (OpenAI, Claude, Gemini, Grok,
  OpenRouter, DeepSeek, Mistral, Groq, Ollama, özel OpenAI-uyumlu) → yerel
  analiz (son çare).

---

## API

| Metot | Yol | Açıklama |
| --- | --- | --- |
| `POST` | `/api/scans` | `{domain, scan_type, authorized}` → `{id, status}` |
| `GET` | `/api/scans` | Tarama geçmişi (sayfalı) |
| `GET` | `/api/scans/{id}` | Durum, progress, bulgular, subdomain'ler |
| `GET` | `/api/scans/{id}/findings` | `?severity=&type=&q=&include_fp=` |
| `GET` | `/api/scans/{id}/subdomains` | `?alive=true` |
| `GET` | `/api/scans/{id}/stats` | Severity dağılımı, risk, motor bilgisi |
| `GET` | `/api/scans/{id}/logs` | `?after_id=` canlı log akışı (polling) |
| `POST` | `/api/scans/{id}/report` | `{format: pdf\|json}` → dosya |
| `GET` | `/api/providers` | Desteklenen AI sağlayıcıları + yapılandırma durumu |
| `GET` / `PUT` | `/api/settings` | AI seçimi / anahtar / model (anahtarlar maskelenir) |
| `GET` | `/api/scans/diff?from=&to=` | İki tarama arası bulgu/risk farkı |
| `GET` | `/ws/scans/{id}` | WebSocket canlı log stream |

Örnek:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"domain":"testphp.vulnweb.com","scan_type":"fast","authorized":true}'
```

---

## Veritabanı Şeması

- **scans:** `id, target_domain, scan_type, status, progress, current_stage,
  risk_score, authorized, error, meta, created_at, completed_at`
- **findings:** `id, scan_id, type, title, severity, cvss, url, evidence,
  ai_analysis, exploit_scenario, fix_code, is_false_positive, owasp_category`
- **subdomains:** `id, scan_id, subdomain, ip, is_alive, technologies, ports`
- **scan_logs:** `id, scan_id, level, message, ts`

---

## Geliştirme (docker olmadan)

```bash
# Backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
DATABASE_URL=sqlite:///./data/raven.db DATA_DIR=./data \
  .venv/bin/uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
BACKEND_URL=http://127.0.0.1:8000 npm run dev
```

Binary olmadan çalıştırmak için `SCANNER_BIN_DIR=/nonexistent` ve `DEMO_MODE=true`
kullanılabilir; bu durumda RAVEN yerleşik Python motorunu veya sentetik demo
verisini kullanır.

---

## Yasal Uyarı (Legal Disclaimer)

> **RAVEN yalnızca yetkili güvenlik testleri içindir.** Bu aracı yalnızca sizin
> sahip olduğunuz, size ait olduğu yazılı olarak belirtilen veya açıkça izin
> verdiğiniz sistemlerde kullanın. Bir sisteme izinsiz erişim, tarama veya test
> yapmak birçınılçül yasaya göre **suç** olup hukuki ve cezai sorumluluk
> doğurur. RAVEN geliştiricileri, kullanıcının eylemlerinden sorumlu değildir.
> Uygulamayı başlattığınızda hedefinizin yetkili olduğunu kabul etmiş olursunuz.
> Tüm taramaların denetlenebilir olması için yasal onay kutusu zorunludur.

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=argenatechlabs/RAVEN&type=Date)](https://star-history.com/#argenatechlabs/RAVEN&Date)

---

<p align="center">
  <sub>bugbounty · pentest · nuclei · security · ai · automation</sub>
</p>
