project('liburing', ['c','cpp'],
        version: run_command('awk', '/Version:/ { print $2 }', 'liburing.spec').stdout().strip(),
        license: ['MIT', 'LGPL-2.1-only', 'GPL-2.0-only WITH Linux-syscall-note'],
        meson_version: '>=0.53.0',
        default_options: ['default_library=both',
                          'buildtype=debugoptimized',
                          'c_std=c11',
                          'cpp_std=c++11',
                          'warning_level=3'])

add_project_arguments('-D_GNU_SOURCE',
                      '-D__SANE_USERSPACE_TYPES__',
                      '-include', meson.current_build_dir() + '/config-host.h',
                      '-Wno-unused-parameter',
                      '-Wno-sign-compare',
                      '-fomit-frame-pointer',
                      language: ['c', 'cpp'])

thread_dep = dependency('threads')

cc = meson.get_compiler('c')

code = '''#include <linux/fs.h>
int main(int argc, char **argv)
{
  __kernel_rwf_t x;
  x = 0;
  return x;
}
'''
has__kernel_rwf_t = cc.compiles(code, name : '__kernel_rwf_t')

code = '''#include <linux/time.h>
#include <linux/time_types.h>
int main(int argc, char **argv)
{
  struct __kernel_timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 1;
  return 0;
}
'''
has__kernel_timespec = cc.compiles(code, name : '__kernel_timespec')

code = '''#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
int main(int argc, char **argv)
{
  struct open_how how;
  how.flags = 0;
  how.mode = 0;
  how.resolve = 0;
  return 0;
}
'''
has_open_how = cc.compiles(code, name: 'open_how')

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

cpp = meson.get_compiler('cpp')

code = '''#include <iostream>
int main(int argc, char **argv)
{
  std::cout << "Test";
  return 0;
}
'''
has_cxx = cpp.compiles(code, name: 'C++')

code = '''#include <ucontext.h>
int main(int argc, char **argv)
{
  ucontext_t ctx;
  getcontext(&ctx);
  return 0;
}
'''
has_ucontext = cc.compiles(code, name : 'ucontext')

conf_data = configuration_data()
conf_data.set('CONFIG_HAVE_KERNEL_RWF_T', has__kernel_rwf_t)
conf_data.set('CONFIG_HAVE_KERNEL_TIMESPEC', has__kernel_timespec)
conf_data.set('CONFIG_HAVE_OPEN_HOW', has_open_how)
conf_data.set('CONFIG_HAVE_STATX', has_statx)
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
