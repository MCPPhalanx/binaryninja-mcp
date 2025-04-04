import pytest


def test_cli_load():
	from binaryninja_mcp.cli import cli

	with pytest.raises(SystemExit) as excinfo:
		cli(['--help'])
	assert excinfo.value.code == 0


def test_binja_plugin_version():
	import json

	with open('plugin.json') as f:
		plugin = json.load(f)

	pip_package, pip_version = plugin['dependencies']['pip'][0].split('==', maxsplit=1)
	json_version = plugin['version']
	assert pip_package == 'binaryninja-mcp'
	assert pip_version == json_version


if __name__ == '__main__':
	test_cli_load()
	test_binja_plugin_version()
	print('smoke test done!')
