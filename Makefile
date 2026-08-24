.PHONY: install dev test lint api worker web demo docker-up docker-down package

install:
	python -m pip install -e .

dev:
	python -m pip install -e '.[dev]'

test:
	pytest --cov=snowimpact --cov-report=term-missing

lint:
	ruff check snowimpact tests
	mypy snowimpact

api:
	uvicorn snowimpact.api.app:app --host 0.0.0.0 --port 8080 --reload

worker:
	python -m snowimpact.workflows.worker

web:
	cd web && npm run dev

demo:
	snowimpact demo

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

package:
	cd .. && zip -r snowimpact-source.zip snowimpact -x 'snowimpact/.git/*' 'snowimpact/web/node_modules/*' 'snowimpact/web/.next/*'
