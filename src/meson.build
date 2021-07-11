subdir('include')

inc = include_directories(['include', '.'])

liburing = library('uring',
                   'queue.c',
                   'register.c',
                   'setup.c',
                   'syscall.c',
                   include_directories : inc,
                   version : lib_version,
                   link_args: '-Wl,--version-script=' + meson.current_source_dir() + '/liburing.map',
                   link_depends: 'liburing.map',
                   install : true)

uring = declare_dependency(link_with: liburing,
                           include_directories: inc)
