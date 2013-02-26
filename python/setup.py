from distutils.core import setup

setup(
    name='tskmon-client',
    version='0.1a1',
    url='https://github.com/cgranade/tskmon-client',
    author='Chris Granade',
    author_email='cgranade@cgranade.com',
    package_dir={'': 'src'},
    packages=[
        'tskmon'
    ]
)
