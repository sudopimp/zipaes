# zipaes — tareas de desarrollo
#
#   make install   instalación editable + herramientas de desarrollo
#   make test      corre la suite
#   make check     lint + formato + tests (lo que corre la CI)
#   make cli       prueba de humo del CLI
#   make demo      crea un zip AES de demostración
#
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

.PHONY: help venv install test cov lint fmt check cli demo clean

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

venv: ## crea el entorno virtual local
	python3 -m venv .venv
	$(PIP) install --upgrade pip

install: ## instala el paquete en modo editable con las dependencias de desarrollo
	$(PIP) install -e ".[dev]"

test: ## corre las pruebas
	$(PY) -m pytest

cov: ## pruebas con cobertura
	$(PY) -m pytest --cov=zipaes --cov-report=term-missing

lint: ## análisis estático
	$(PY) -m ruff check zipaes tests

fmt: ## formato y correcciones automáticas
	$(PY) -m ruff check --fix zipaes tests
	$(PY) -m ruff format zipaes tests

check: lint ## lo mismo que corre la integración continua
	$(PY) -m ruff format --check zipaes tests
	$(PY) -m pytest

cli: ## prueba de humo del CLI
	$(PY) -m zipaes.cli --version
	$(PY) -m zipaes.cli selftest
	$(PY) -m zipaes.cli info --help >/dev/null && echo "ayuda del CLI: ok"

demo: ## genera un zip AES de demostración en /tmp
	$(PY) -c "from zipaes.testkit import write_aes_zip; \
	write_aes_zip('/tmp/demo.zip', {'nota.txt': b'hola mundo'}, 'clave-demo'); \
	print('creado /tmp/demo.zip con la contrasena clave-demo')"
	$(PY) -m zipaes.cli info /tmp/demo.zip
	$(PY) -m zipaes.cli verify /tmp/demo.zip -p clave-demo

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov build dist *.egg-info
	find . -name __pycache__ -type d -not -path './.venv/*' -exec rm -rf {} +