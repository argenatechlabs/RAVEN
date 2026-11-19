<p align="center">
  <img src="docs/demo.gif" alt="RAVEN demo" width="720" />
</p>

# RAVEN — Autonomous AI Pentester

<p align="center">
  <img src="https://img.shields.io/badge/status-MVP-00ff41?style=for-the-badge" alt="status" />
  <img src="https://img.shields.io/badge/python-3.11-00b32d?style=for-the-badge&logo=python" alt="python" />
  <img src="https://img.shields.io/badge/frontend-Next.js_15-00ff41?style=for-the-badge&logo=nextdotjs" alt="nextjs" />
  <img src="https://img.shields.io/badge/scanners-nuclei_9000%2B-00b32d?style=for-the-badge" alt="nuclei" />
  <img src="https://img.shields.io/badge/AI-OpenAI_|_Claude_|_Gemini_|_Grok_|_Ollama-00ff41?style=for-the-badge" alt="ai" />
  <img src="https://img.shields.io/badge/license-MIT-6b7280?style=for-the-badge" alt="license" />
</p>

**Domain gir → 5 dakikada otomatik sızma testi → AI analizi → profesyonel PDF rapor.**

RAVEN; bug bounty hunter, KOBİ/startup, SOC ekipleri ve öğrenciler için tek tıkla
çalıştırılabilen, kendi kendine yeten bir güvenlik tarama platformudur. Tarayıcıdan
hedef girersiniz, canlı logları izlersiniz, bulguları AI analiziyle okursunuz ve tek
tıkla PDF/JSON rapor alırsınız.

<p align="center">
  <a href="https://raven.example.com"><strong>▶ Live Demo</strong></a> ·
  <a href="#1-gereksinimler">Kurulum</a> ·
  <a href="#3-ilk-taramayı-arayüzden-yapmak">İlk Tarama</a> ·
  <a href="#4-ai-saglayicisi-secmek">AI Seçimi</a> ·
  <a href="#8-sorun-giderme">Sorun Giderme</a>
</p>

> **Not:** Bu depo bir MVP'dir. Continuous monitoring, SSO/RBAC, organizasyon
> yapısı, Slack/Jira entegrasyonu, HTML/Excel rapor gibi özellikler bilinçli olarak
> kapsam dışı bırakılmıştır.

---

## İçindekiler

1. [Gereksinimler](#1-gereksinimler)
2. [Tek komutla kurulum (Docker — önerilen)](#2-tek-komutla-kurulum-docker--onerilen)
3. [İlk taramayı arayüzden yapmak](#3-ilk-taramayı-arayüzden-yapmak)
4. [AI sağlayıcısı seçmek (OpenAI, Claude, Gemini, Grok, …)](#4-ai-sağlayıcısı-seçmek-openai-claude-gemini-grok-)
5. [Docker olmadan çalıştırmak (geliştirme)](#5-docker-olmadan-çalıştırmak-geliştirme)
6. [API ile kullanmak](#6-api-ile-kullanmak)
7. [Yapılandırma (env)](#7-yapılandırma-env)
8. [Sorun giderme](#8-sorun-giderme)
9. [Mimari](#9-mimari)
10. [Özellikler](#10-özellikler)
11. [Veritabanı şeması](#11-veritabanı-şeması)
12. [Yasal uyarı](#yasal-uyarı-legal-disclaimer)

---

## 1. Gereksinimler

**Önerilen yol (Docker):**

| Gereksinim | Minimum | Not |
| --- | --- | --- |
| Docker Engine | 24+ | `docker --version` |
| Docker Compose | v2.x (`docker compose`) | `docker compose version` |
| Bağlantı | İlk build'de GitHub release'lerine açık | scanner binary'leri indirilir |
| Disk | ~4 GB boş | imajlar + nuclei şablonları |
| RAM | 4 GB | 8 GB önerilir |

**Docker olmadan (geliştirme):** Python 3.11, Node.js 20+, isteğe bağlı
PostgreSQL 15 ve Redis 7 (ikisi de yoksa RAVEN SQLite + inline worker ile çalışır).
Tarayıcı binary'leri için ağ erişimi gerekir (bkz. [Bölüm 5](#5-docker-olmadan-çalıştırmak-geliştirme)).

---

## 2. Tek komutla kurulum (Docker — önerilen)

```bash
# 1) Depoyu klonla
git clone https://github.com/argenatechlabs/RAVEN.git
cd RAVEN

# 2) Ortam değişkenlerini oluştur (opsiyonel ama önerilir)
cp .env.example .env
# .env içine istersen OPENAI_API_KEY=..., XAI_API_KEY=... gibi anahtarlar ekle.
# Anahtarsız da çalışır: AI ayarları arayüzden sonradan girilebilir (Bölüm 4).

# 3) Tüm sistemi ayağa kaldır
docker compose up --build
```

İlk `build` sırasında şunlar yapılır:

1. Backend imajına gömülü scanner binary'leri indirilir:
   **subfinder v2.17.0, httpx v1.12.0, katana v1.8.0, nuclei v3.11.1**.
2. nuclei şablon seti (~9.000+ imza) indirilir.
3. Frontend Next.js production build alınır.

Bu yüzden ilk build **birkaç dakika** sürebilir; sonraki çalıştırmalar
`docker compose up` ile saniyeler içinde açılır.

### Ne zaman hazır?

Aşağıdaki komutun `ok` döndürdüğünü gördüğünüzde hazır:

```bash
curl http://localhost:8000/api/health
# {"status":"ok", ...}
```

### Açılacak adresler

| Servis | Adres | Ne işe yarar |
| --- | --- | --- |
| **Frontend (Dashboard)** | http://localhost:3000 | Tarama arayüzü |
| **Backend API** | http://localhost:8000 | REST API |
| **API Dokümantasyonu** | http://localhost:8000/docs | Swagger UI |
| PostgreSQL | `localhost:5432` (iç ağ) | Veritabanı |
| Redis | `localhost:6379` (iç ağ) | Tarama kuyruğu |

### Yaygın çalıştırma komutları

```bash
docker compose up --build          # ön planda başlat (logları gösterir)
docker compose up -d --build       # arka planda başlat
docker compose ps                  # servis durumları
docker compose logs -f backend     # backend logları (canlı)
docker compose logs -f frontend    # frontend logları
docker compose restart backend     # backend'i yeniden başlat
docker compose down                # durdur (veriler korunur)
docker compose down -v             # durdur + verileri sil (DB sıfırlama)
```

> Veriler `pgdata`, `redisdata`, `raven_data` volume'larında tutulur; `down`
> verileri silmez, `down -v` siler.

---

## 3. İlk taramayı arayüzden yapmak

1. Tarayıcıda **http://localhost:3000** açın.
2. Orta alandaki **"testphp.vulnweb.com"** yazan kutuya hedef domain'i yazın.
   - Örnek: `testphp.vulnweb.com`, `example.com` veya izinli bir sizin hedefiniz.
   - Protokol girmeyin (`https://example.com` yerine `example.com`).
3. **Hızlı / Derin** seçeneğini belirleyin:
   - *Hızlı*: kritik/yüksek/orta nuclei seviyeleri, crawler derinliği 2.
   - *Derin*: + düşük seviye, crawler derinliği 3.
4. **"Sadece izinli hedeflerde tarama yapacağımı onaylıyorum"** kutusunu işaretleyin.
   - Bu onay zorunludur; işaretlenmezse API 403 döner.
5. **AI Sağlayıcı** açılır listesinden bir model seçin (varsayılan: *Otomatik*).
   - İlk kez kullanıyorsanız bkz. [Bölüm 4](#4-ai-sağlayıcısı-seçmek-openai-claude-gemini-grok-).
   - Anahtar girilmediyse RAVEN yerel analiz motorunu kullanır; tarama yine tamamlanır.
6. **Tara** butonuna basın. Yeni sekme `/scan/<id>` açılır.

### Tarama ekranında ne göreceksiniz?

| Bölüm | Ne gösterir |
| --- | --- |
| Üst bar | Domain, durum (queued/scanning/completed/failed), **AI rozeti**, PDF/JSON indirme |
| Risk skoru | 0–100 arası halka gösterge |
| İlerleme | Anlık aşama (Recon → Crawler → Zafiyet → Secret → AI Triage → Rapor) |
| Sol panel | **Canlı log terminali** (2 sn'de bir yenilenir) |
| Orta panel | Bulgular tablosu: severity filtresi, arama, false positive gösterimi |
| Sağ panel | **Subdomain ağacı** (canlı/ölü + teknoloji rozetleri) |

Bir satıra tıklayınca **detay drawer**'ı açılır: AI analizi, sömürü senaryosu,
kanıt (evidence), OWASP kategorisi ve **düzeltme/fix kodu**.

Tarama bitince **PDF İndir** / **JSON** butonları aktif olur.

### Geçmiş ve fark

`/history` sayfasında tüm taramalar listelenir; filtre + **Tekrar tara**
bulunur. Ayrıca iki taramayı seçip **Karşılaştır** derseniz yeni/giderilen
bulguları ve risk değişimini gösterir.

---

## 4. AI sağlayıcısı seçmek (OpenAI, Claude, Gemini, Grok, …)

RAVEN, **istediğiniz her AI'yi** kullanmanızı sağlar:

| Sağlayıcı | Model örneği | Env anahtarı |
| --- | --- | --- |
| OpenAI (GPT) | `gpt-4o-mini` | `OPENAI_API_KEY` |
| Anthropic (Claude) | `claude-sonnet-4-5` | `ANTHROPIC_API_KEY` |
| Google Gemini | `gemini-2.5-flash` | `GEMINI_API_KEY` |
| **xAI (Grok)** | `grok-3` | `XAI_API_KEY` |
| OpenRouter | `anthropic/claude-sonnet-4.5` | `OPENROUTER_API_KEY` |
| DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| Mistral | `mistral-large-latest` | `MISTRAL_API_KEY` |
| Groq | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| Ollama (Yerel) | `llama3.1` | `OLLAMA_URL` |
| Özel (OpenAI uyumlu) | sizin modeliniz | `CUSTOM_API_KEY` |

### Arayüzden (önerilen)

1. Ana sayfadaki **AI Sağlayıcı** açılır listesinde sağlayıcıyı seçin.
   Seçim anında kaydedilir.
2. Yanındaki **API Anahtarı / Model** butonuna basın.
3. Açılan pencerede:
   - **Model** alanını doldurun (ör. `grok-3`).
     - **API Anahtarı** alanına anahtarı yapıştırın (kaynak anahtar maskelenmiş
     gösterilir; değiştirmek için yenisini yazın).
   - **Özel** seçiliyse **Base URL** alanı belirir.
4. **Kaydet** → artık tüm taramalar bu sağlayıcıyı kullanır.

Örnek — Grok kullanmak:

```text
Sağlayıcı : xAI (Grok)
Model     : grok-3
API Anahtarı: gsk_xxxxxxxxxxxx        # x.ai API anahtarınız
```

### Env ile (headless / sunucu)

`.env`'e anahtarları yazın ve `docker compose up -d` ile yeniden başlatın:

```bash
OPENAI_API_KEY=sk-...
XAI_API_KEY=gsk_...
GEMINI_API_KEY=...
```

### API ile

```bash
curl http://localhost:8000/api/providers        # hangileri yapılandırılmış?
curl http://localhost:8000/api/settings         # aktif seçim + maskeli anahtarlar

curl -X PUT http://localhost:8000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"provider":"xai","api_key":"gsk_...","model":"grok-3"}'
```

### Davranış kuralları

- Anahtarlar veritabanında saklanır ve API'de **asla** açık döndürülmez
  (maskeli: `gsk_••••abcd`).
- Seçim kalıcıdır. Tek bir tarama farklı AI istiyorsa `POST /api/scans`'e
  `"ai_provider": "gemini"` ekleyin.
- Sağlayıcı bulunamaz / anahtar hatalı / ağ hatası olursa RAVEN otomatik
  **yerel analiz** motoruna geçer; bulgular boş kalmaz, log'da uyarı görünür.
- Kullanılan sağlayıcı tarama sayfasında `AI: <provider> · <model>` rozetiyle
  görünür.

---

## 5. Docker olmadan çalıştırmak (geliştirme)

### A) Sıfır konfigürasyon (SQLite + inline worker) — hızlı deneme

PostgreSQL/Redis kurmadan, backend kendi SQLite veritabanını ve iç kuyruğunu
kullanır; scanner binary'si yoksa yerleşik Python motoruna düşer:

```bash
# Backend
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# → http://localhost:8000/docs

# Frontend (yeni terminal)
cd frontend
npm install
BACKEND_URL=http://127.0.0.1:8000 npm run dev
# → http://localhost:3000
```

Bu modda gerçek scanner binary'leri olmadığı için `builtin-dns`,
`builtin-http`, `builtin-crawler`, `builtin` (nuclei fallback) motorları
kullanılır. `DEMO_MODE=true` eklerseniz sentetik hedefle uçtan uca test
yapabilirsiniz.

### B) Scanner binary'lerini yerelde kullanma

Binary'leri [projectdiscovery](https://github.com/projectdiscovery) release'lerinden
indirip bir klasöre koyun ve `SCANNER_BIN_DIR`'i ona göre ayarlayın:

```bash
mkdir -p ~/raven-bin && cd ~/raven-bin
curl -L -o subfinder.zip  https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_amd64.zip && unzip subfinder.zip && chmod +x subfinder
curl -L -o httpx.zip      https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip && unzip httpx.zip && chmod +x httpx
curl -L -o katana.zip     https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip && unzip katana.zip && chmod +x katana
curl -L -o nuclei.zip     https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip && unzip nuclei.zip && chmod +x nuclei

cd backend
SCANNER_BIN_DIR=$HOME/raven-bin .venv/bin/uvicorn app.main:app --reload
# nuclei şablonları ilk çalıştırmada ~/nuclei-templates'e iner
```

### C) Tam prodüksiyon benzeri yerel kurulum

```bash
# PostgreSQL + Redis (Docker'da)
docker run -d --name raven-pg -p 5432:5432 -e POSTGRES_USER=raven \
  -e POSTGRES_PASSWORD=raven -e POSTGRES_DB=raven postgres:15-alpine
docker run -d --name raven-redis -p 6379:6379 redis:7-alpine

cd backend
DATABASE_URL=postgresql+psycopg2://raven:raven@localhost:5432/raven \
REDIS_URL=redis://localhost:6379/0 \
SCANNER_BIN_DIR=$HOME/raven-bin \
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# İsteğe bağlı: migration ile şemayı uygula (startup zaten create_all yapar)
cd backend && DATABASE_URL=postgresql+psycopg2://raven:raven@localhost:5432/raven \
  .venv/bin/alembic upgrade head
```

---

## 6. API ile kullanmak

| Metot | Yol | Açıklama |
| --- | --- | --- |
| `POST` | `/api/scans` | `{domain, scan_type, authorized, ai_provider?}` → `{id, status}` |
| `GET` | `/api/scans` | Tarama geçmişi (sayfalı) |
| `GET` | `/api/scans/{id}` | Durum, progress, bulgular, subdomain'ler |
| `GET` | `/api/scans/{id}/findings` | `?severity=&type=&q=&include_fp=` |
| `GET` | `/api/scans/{id}/subdomains` | `?alive=true` |
| `GET` | `/api/scans/{id}/stats` | Severity dağılımı, risk, motor bilgisi |
| `GET` | `/api/scans/{id}/logs` | `?after_id=` canlı log akışı |
| `POST` | `/api/scans/{id}/report` | `{format: pdf\|json}` → dosya |
| `GET` | `/api/scans/{id}/report?format=pdf` | Doğrudan indirme |
| `GET` | `/api/scans/diff?from=&to=` | İki tarama arası bulgu/risk farkı |
| `GET` | `/api/providers` | Desteklenen AI sağlayıcıları + yapılandırma durumu |
| `GET` / `PUT` | `/api/settings` | AI seçimi / anahtar / model (anahtarlar maskelenir) |
| `GET` | `/ws/scans/{id}` | WebSocket canlı log stream |
| `GET` | `/api/health` | Sağlık kontrolü |

Örnek akış:

```bash
# 1) Tarama başlat
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"domain":"testphp.vulnweb.com","scan_type":"fast","authorized":true,"ai_provider":"xai"}'

# → {"id": 1, "status": "queued", ...}

# 2) Canlı durum
curl http://localhost:8000/api/scans/1 | jq '.status, .progress, .risk_score'

# 3) Loglar (polling)
curl "http://localhost:8000/api/scans/1/logs?after_id=0" | jq '.items[-3:]'

# 4) Bulgular (false positive'lar hariç)
curl "http://localhost:8000/api/scans/1/findings?severity=critical" | jq '.items'

# 5) Rapor
curl -X POST http://localhost:8000/api/scans/1/report \
  -H 'Content-Type: application/json' -d '{"format":"pdf"}' -o rap.pdf
```

---

## 7. Yapılandırma (env)

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `AI_PROVIDER` | `auto` | `auto` \| `openai` \| `anthropic` \| `gemini` \| `xai` \| `openrouter` \| `deepseek` \| `mistral` \| `groq` \| `ollama` \| `custom` \| `local` |
| `<SAĞLAYICI>_API_KEY` | boş | OpenAI, Anthropic, Gemini, xAI, OpenRouter, DeepSeek, Mistral, Groq, Custom |
| `<SAĞLAYICI>_MODEL` | görünümdeki | Kullanılacak model adı |
| `<SAĞLAYICI>_BASE_URL` | boş | Özel uç nokta |
| `OLLAMA_URL` | `http://ollama:11434` | Ollama adresi |
| `DEMO_MODE` | `false` | Binary/hedef olmadan uçtan uca demo çalıştırır |
| `SCANNER_TIMEOUT` | `1200` | Tarayıcılar için maksimum süre (sn) |
| `NUCLEI_SEVERITIES` | `critical,high,medium` | nuclei seviyeleri |
| `DATABASE_URL` | `postgresql+psycopg2://…` | Compose otomatik ayarlar |
| `REDIS_URL` | `redis://redis:6379/0` | Compose otomatik ayarlar |
| `CORS_ORIGINS` | `["*"]` | API CORS ayarları |

Tüm anahtarlar `.env`'e yazılabilir; `cp .env.example .env` ile başlayın.

---

## 8. Sorun giderme

| Belirti | Olası neden | Çözüm |
| --- | --- | --- |
| `docker compose up` "port is already allocated" | 3000/8000/5432/6379 dolu | `docker compose down` sonra başka servisleri durdurun; ya da `docker-compose.yml`'de portları değiştirin |
| İlk build çok uzun sürüyor / binary indirme hatası | Ağ github release'lerine kısıtlı | İnterneti kontrol edin; binary'leri manuel indirip `SCANNER_BIN_DIR`'e göre `.env`'e ekleyin |
| Frontend "Internal Server Error" | Backend değil / build'de `BACKEND_URL` yanlış | `docker compose logs backend`; frontend build arg'ı `http://backend:8000` olmalı |
| Tarama "failed" oluyor | Tarayıcı hatası / hedef yok | Tarama sayfasındaki loglara bakın; `docker compose logs backend --tail=100` |
| Bulgular "yerel analiz" diyor | AI anahtarı yok/hatalı veya ağ hatası | Bölüm 4; `GET /api/settings` ile durumu kontrol edin |
| PDF indirme butonu pasif | Tarama henüz bitmedi | `status: completed` olana kadar bekleyin |
| Verileri sıfırlamak istiyorum | — | `docker compose down -v` (volume'ları siler) |
| AI sağlayıcısı listede "✓" yok | Anahtar/URL eksik | Modal'dan anahtar girin ya da `.env`'e ekleyip yeniden başlatın |
| 9.000+ imza taraması beklediğim gibi çalışmıyor | nuclei şablonları indirilemedi | Konteynerde `nuclei -update-templates` çalıştırın; loglara bakın |

Logları canlı izlemek için:

```bash
docker compose logs -f backend          # tüm backend logları
docker compose logs -f frontend         # Next.js logları
curl http://localhost:8000/api/scans/1/logs | jq .
```

> **Henüz bir kullanıcı/giriş sistemi yoktur** (MVP kapsamı dışı). Arayüzü açtığınız
> makine ağınızda erişilebilir olursa, 3000/8000 portlarını güvenlik duvarında
> kısıtlayın.

---

## 9. Mimari

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

- **Backend:** Python 3.11, FastAPI, SQLAlchemy 2.0, Alembic, Redis.
- **Veritabanı:** PostgreSQL 15 (`scans`, `findings`, `subdomains`, `scan_logs`, `settings`).
- **Tarayıcılar:** Docker imajına gömülü binary'ler, `subprocess` ile çağrılır;
  hedefe saniyede en fazla 10 istek (`-rate-limit 10`).
- **Frontend:** Next.js 15 App Router, TypeScript, Tailwind CSS, Lucide Icons.
- **AI:** Kullanıcının seçtiği sağlayıcı → yerel analiz (son çare).

---

## 10. Özellikler

- **Tek tıkla tarama:** Domain + Tara; yasal onay zorunludur.
- **Recon:** subfinder ile alt alan, httpx ile canlı kontrol + teknoloji tespiti.
- **Crawler:** katana ile endpoint ve JavaScript toplama.
- **Zafiyet taraması:** nuclei ile 9.000+ imza (kritik/yüksek/orta; derin modda +düşük).
- **Secret scan:** AWS, GitHub, GitLab, Slack, Google, Stripe, JWT, private key, generic secret.
- **AI triage:** İstediğiniz sağlayıcıyı seçin — false positive eleme, severity, CVSS,
  sömürü senaryosu, OWASP, fix kodu. Sağlayıcı yoksa yerel analiz devreye girer.
- **Canlı ilerleme:** polling + WebSocket, canlı log terminali, risk skoru.
- **Sonuçlar:** severity filtresi, arama, false positive gösterimi, detay drawer.
- **Harita:** Subdomain ağacı görselleştirmesi.
- **Rapor:** Tek tıkla PDF (reportlab) ve JSON export.
- **Geçmiş:** Liste, filtre, tekrar tara, iki tarama arası diff.
- **Hata yönetimi:** Binary yoksa fallback motor, hatalar loglanır.

---

## 11. Veritabanı şeması

- **scans:** `id, target_domain, scan_type, status, progress, current_stage,
  risk_score, authorized, error, meta, created_at, completed_at`
- **findings:** `id, scan_id, type, title, severity, cvss, url, evidence,
  ai_analysis, exploit_scenario, fix_code, is_false_positive, owasp_category`
- **subdomains:** `id, scan_id, subdomain, ip, is_alive, technologies, ports`
- **scan_logs:** `id, scan_id, level, message, ts`
- **settings:** `key, value, is_secret, updated_at` (AI sağlayıcı yapılandırması)

Migration: `docker compose exec backend alembic upgrade head`

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
