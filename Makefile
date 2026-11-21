# RAVEN — tek komutla kurulum ve geliştirme yardımcıları.
COMPOSE ?= docker compose

.PHONY: up down logs ps build restart clean test backend-test frontend-test fmt demo

up: ## Tüm stack'i ayağa kaldır
	$(COMPOSE) up -d --build

down: ## Stack'i durdur (veriler korunur)
	$(COMPOSE) down

restart: ## Yeniden başlat
	$(COMPOSE) restart

logs: ## Tüm servis loglarını izle
	$(COMPOSE) logs -f --tail=100

ps: ## Servis durumları
	$(COMPOSE) ps

build: ## İmajları yeniden derle
	$(COMPOSE) build

clean: ## Stack'i durdur ve volumeleri sil
	$(COMPOSE) down -v

backend-test: ## Backend testleri (lokal venv)
	cd backend && .venv/bin/python -m pytest

frontend-test: ## Frontend derlemesi (tip kontrolü)
	cd frontend && npm run build

test: backend-test frontend-test ## Tüm testler

fmt: ## Python kaynaklarına düzen uygula (ruff yüklüyse)
	cd backend && .venv/bin/ruff format app tests || true

demo: ## docs/demo.gif'i canli taramadan yeniden üret (SCAN_ID=12 make demo)
	@test -n "$(SCAN_ID)" || { echo "Kullanım: make demo SCAN_ID=12"; exit 2; }
	cd backend && .venv/bin/python ../docs/make_demo_gif.py --api http://127.0.0.1:8000 --scan $(SCAN_ID)
