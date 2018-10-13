from setuptools import setup

setup(name=                 'micro5sim',
      version=              '0.1',
      description=          'ISS for micro5 RISC-V core',
      url=                  'http://github.com/jaruiz/micro5sim',
      author=               'Jose A. Ruiz',
      author_email=         'jose.a.ruiz.dominguez.eu@gmail.com',
      license=              'Apache 2.0',
      packages=             ['micro5sim'],
      package_dir=          {'micro5sim': 'micro5sim'},
      entry_points=         {
                                'console_scripts': [
                                    'micro5sim=micro5sim.cli:main'
                                ],
                            },
      install_requires=     ["pyelftools"],
      zip_safe=             True
      )
