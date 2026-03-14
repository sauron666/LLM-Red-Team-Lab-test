.PHONY: run gui cli help lint compile zip

help:
	python main_cli.py --help

gui:
	python main.py

cli:
	python main_cli.py --help

compile:
	python -m compileall llm_attack_lab main.py main_cli.py main_bridge.py

zip:
	cd .. && zip -r llm_attack_lab_release.zip llm_attack_lab_project -x "*/__pycache__/*" "*.pyc"
