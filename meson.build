project('liburing', ['c','cpp'],
        version: run_command('awk', '/Version:/ { print $2 }', 'liburing.spec', check: true).stdout().strip(),
        license: ['MIT', 'LGPL-2.1-only', 'GPL-2.0-only WITH Linux-syscall-note'],
        meson_version: '>=0.53.0',
        default_options: ['default_library=both',
                          'buildtype=debugoptimized',
                          'c_std=c11',
                          'cpp_std=c++11',
                          'optimization=3',
                          'warning_level=2'])

add_project_arguments('-D_GNU_SOURCE',
                      '-D__SANE_USERSPACE_TYPES__',
                      '-include', meson.current_build_dir() + '/config-host.h',
                      '-Wno-unused-parameter',
                      '-Wno-sign-compare',
                      language: ['c', 'cpp'])

thread_dep = dependency('threads')

cc = meson.get_compiler('c')

has__kernel_rwf_t = cc.has_type('__kernel_rwf_t', prefix: '#include <linux/fs.h>')

has__kernel_timespec = cc.has_members('struct __kernel_timespec',
                                      'tv_sec',
                                      'tv_nsec',
                                      prefix: '#include <linux/time.h>')

has_open_how = cc.has_members('struct open_how',
                                      'flags',
                                      'mode',
                                      'resolve',
                                      prefix: '#include <linux/openat2.h>')

code = '''#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/stat.h>
int main(int argc, char **argv)
{
  struct statx x;

  return memset(&x, 0, sizeof(x)) != NULL;
}
'''
has_statx = cc.compiles(code, name: 'statx')

code= '''#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/stat.h>
main(int argc, char **argv)
{
  struct statx x;

  return memset(&x, 0, sizeof(x)) != NULL;
}
'''
glibc_statx = cc.compiles(code, name: 'glibc_statx')

# Since the project is configured to use C++
# meson fails if no C++ compiler is available.
has_cxx = true

has_ucontext = (cc.has_type('ucontext_t', prefix: '#include <ucontext.h>')
  and cc.has_function('makecontext', prefix: '#include <ucontext.h>'))

conf_data = configuration_data()
conf_data.set('CONFIG_HAVE_KERNEL_RWF_T', has__kernel_rwf_t)
conf_data.set('CONFIG_HAVE_KERNEL_TIMESPEC', has__kernel_timespec)
conf_data.set('CONFIG_HAVE_OPEN_HOW', has_open_how)
conf_data.set('CONFIG_HAVE_STATX', has_statx)
conf_data.set('CONFIG_HAVE_GLIBC_STATX', glibc_statx)
conf_data.set('CONFIG_HAVE_CXX', has_cxx)
conf_data.set('CONFIG_HAVE_UCONTEXT', has_ucontext)
configure_file(output: 'config-host.h',
               configuration: conf_data)

subdir('src')
subdir('man')

if get_option('examples')
    subdir('examples')
endif

if get_option('tests')
    if get_option('default_library') != 'both'
        error('default_library=both required to build tests')
    endif
    subdir('test')
endif

pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries: liburing,
                 name: 'liburing',
                 version: meson.project_version(),
                 description: 'io_uring library',
                 url: 'http://git.kernel.dk/cgit/liburing/')

summary({'bindir': get_option('bindir'),
         'libdir': get_option('libdir'),
         'datadir': get_option('datadir'),
        }, section: 'Directories')
summary({'examples': get_option('examples'),
         'tests': get_option('tests')
        }, section: 'Configuration', bool_yn: true)
