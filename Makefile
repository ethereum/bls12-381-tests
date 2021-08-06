.PHONY: install_ci, lint, generate_yaml, generate_json, clean

install_ci:
	python -m pip install --upgrade pip
	pip install flake8
	pip install -r requirements.txt

lint:
	# stop the build if there are Python syntax errors or undefined names
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics --exclude=venv
	# exit-zero treats all errors as warnings. The GitHub editor is 127 chars wide
	# Ignored:
	#   - E122 continuation line missing indentation or outdented
	#   - E501 line too long
	flake8 . --count --ignore=E122,E501 --max-complexity=10 --max-line-length=127 --statistics --exclude=venv

generate_yaml:
	mkdir -p out/yaml
	python main.py -e=yaml -o=out/yaml -f

generate_json:
	mkdir out/json
	python main.py -e=json -o=out/json -f

clean:
	rm -rf out
