test:
	python -m unittest discover tests

format:
	black .

.PHONY: format

