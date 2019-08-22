project('spielpatz', 'c',
        default_options: ['c_std=c11', 'warning_level=3'])

p11kit  = dependency('p11-kit-1')
openssl = dependency('openssl')

common_lib = static_library('common',
  sources: ['common.c'],
  dependencies: [p11kit, openssl],
  include_directories: [
    include_directories('.')
])

common = declare_dependency(
  dependencies: [p11kit, openssl],
  link_with: common_lib,
  include_directories: [
    include_directories('.')
])

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
                   common,
                   p11kit,
                   openssl])
