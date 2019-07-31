project('spielpatz', 'c',
        default_options: ['c_std=c11', 'warning_level=3'])

p11kit = dependency('p11-kit-1')

executable('list',
           sources: [ 'list.c' ],
           dependencies: [
                   p11kit])
