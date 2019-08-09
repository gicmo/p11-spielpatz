project('spielpatz', 'c',
        default_options: ['c_std=c11', 'warning_level=3'])

p11kit  = dependency('p11-kit-1')
openssl = dependency('openssl')

executable('list',
           sources: [ 'list.c' ],
           dependencies: [
                   p11kit])

executable('watch',
           sources: [ 'watch.c' ],
           dependencies: [
                   p11kit])

executable('cert',
           sources: [ 'cert.c' ],
           dependencies: [
                   p11kit,
                   openssl])

executable('gen',
           sources: [ 'gen.c' ],
           dependencies: [
                   p11kit,
                   openssl])
