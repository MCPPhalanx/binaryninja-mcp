def test_cli_load():
	from binaryninja_mcp.cli import cli

	try:
		cli(['--help'])
	except SystemExit as e:
		assert e.code == 0, 'Exit code != 0'
		print('test_cli_load pass')


def test_binja_plugin_version():
	import json

	with open('plugin.json') as f:
		plugin = json.load(f)
	with open('requirements.txt') as f:
		lines = f.readlines()

	pip_package, pip_version = lines[0].split('==', maxsplit=1)
	json_version = plugin['version']
	assert pip_package == 'binaryninja-mcp'
	assert pip_version == json_version
	print(f'test_binja_plugin_version pass, pip_version == json_version == {json_version}')


if __name__ == '__main__':
	test_cli_load()
	test_binja_plugin_version()
	print('smoke test done!')
