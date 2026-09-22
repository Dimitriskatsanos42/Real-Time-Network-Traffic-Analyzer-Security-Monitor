.PHONY: run test docker-up docker-down

run:
	python app.py

test:
	python -m pytest -q tests

docker-up:
	docker compose up --build

docker-down:
	docker compose down
