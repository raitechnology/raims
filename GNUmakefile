# raims makefile
lsb_dist     := $(shell if [ -f /etc/os-release ] ; then \
                  grep '^NAME=' /etc/os-release | sed 's/.*=[\"]*//' | sed 's/[ \"].*//' ; \
                  elif [ -x /usr/bin/lsb_release ] ; then \
                  lsb_release -is ; else echo Linux ; fi)
lsb_dist_ver := $(shell if [ -f /etc/os-release ] ; then \
		  grep '^VERSION=' /etc/os-release | sed 's/.*=[\"]*//' | sed 's/[ \"].*//' ; \
                  elif [ -x /usr/bin/lsb_release ] ; then \
                  lsb_release -rs | sed 's/[.].*//' ; else uname -r | sed 's/[-].*//' ; fi)
#lsb_dist     := $(shell if [ -x /usr/bin/lsb_release ] ; then lsb_release -is ; else echo Linux ; fi)
#lsb_dist_ver := $(shell if [ -x /usr/bin/lsb_release ] ; then lsb_release -rs | sed 's/[.].*//' ; else uname -r | sed 's/[-].*//' ; fi)
uname_m      := $(shell uname -m)

short_dist_lc := $(patsubst CentOS,rh,$(patsubst RedHatEnterprise,rh,\
                   $(patsubst RedHat,rh,\
                     $(patsubst Fedora,fc,$(patsubst Ubuntu,ub,\
                       $(patsubst Debian,deb,$(patsubst SUSE,ss,$(lsb_dist))))))))
short_dist    := $(shell echo $(short_dist_lc) | tr a-z A-Z)
pwd           := $(shell pwd)
rpm_os        := $(short_dist_lc)$(lsb_dist_ver).$(uname_m)

# this is where the targets are compiled
build_dir ?= $(short_dist)$(lsb_dist_ver)_$(uname_m)$(port_extra)
bind      := $(build_dir)/bin
libd      := $(build_dir)/lib64
objd      := $(build_dir)/obj
dependd   := $(build_dir)/dep

have_asciidoctor := $(shell if [ -x /usr/bin/asciidoctor ] ; then echo true; fi)
have_rpm         := $(shell if [ -x /bin/rpmquery ] ; then echo true; fi)
have_dpkg        := $(shell if [ -x /bin/dpkg-buildflags ] ; then echo true; fi)
default_cflags   := -ggdb -O3
# use 'make port_extra=-g' for debug build
ifeq (-g,$(findstring -g,$(port_extra)))
  default_cflags := -ggdb
endif
ifeq (-a,$(findstring -a,$(port_extra)))
  default_cflags := -fsanitize=address -ggdb -O3
endif
ifeq (-mingw,$(findstring -mingw,$(port_extra)))
  CC    := /usr/bin/x86_64-w64-mingw32-gcc
  CXX   := /usr/bin/x86_64-w64-mingw32-g++
  mingw := true
endif
ifeq (,$(port_extra))
  ifeq (true,$(have_rpm))
    build_cflags = $(shell /bin/rpm --eval '%{optflags}')
  endif
  ifeq (true,$(have_dpkg))
    build_cflags = $(shell /bin/dpkg-buildflags --get CFLAGS)
  endif
endif
# msys2 using ucrt64
ifeq (MSYS2,$(lsb_dist))
  mingw := true
endif
CC          ?= gcc
CXX         ?= g++
cc          := $(CC) -std=c11
cpp         := $(CXX)
arch_cflags := -mavx -maes -fno-omit-frame-pointer
gcc_wflags  := -Wall -Wextra -Werror

# if windows cross compile
ifeq (true,$(mingw))
dll         := dll
exe         := .exe
soflag      := -shared -Wl,--subsystem,windows
fpicflags   := -fPIC -DMS_SHARED
sock_lib    := -lcares -lssl -lcrypto -lws2_32 -lwinmm -liphlpapi
dynlink_lib := -lpcre2-8 -lpcre2-32
NO_STL      := 1
else
dll         := so
exe         :=
soflag      := -shared
fpicflags   := -fPIC
thread_lib  := -pthread -lrt
sock_lib    := -lcares -lssl -lcrypto
dynlink_lib := -lpcre2-8 -lpcre2-32
endif
# make apple shared lib
ifeq (Darwin,$(lsb_dist)) 
dll         := dylib
endif
# rpmbuild uses RPM_OPT_FLAGS
#ifeq ($(RPM_OPT_FLAGS),)
CFLAGS ?= $(build_cflags) $(default_cflags)
#else
#CFLAGS ?= $(RPM_OPT_FLAGS)
#endif
cflags := $(gcc_wflags) $(CFLAGS) $(arch_cflags)
lflags := -Wno-stringop-overflow

INCLUDES  ?= -Iinclude
#-Iraikv/include -Iraimd/include -Iraids/include -Ilinecook/include
DEFINES   ?=
includes  := $(INCLUDES)
defines   := $(DEFINES)

# if not linking libstdc++
ifdef NO_STL
cppflags  := -std=c++11 -fno-rtti -fno-exceptions
cpplink   := $(CC)
else
cppflags  := -std=c++11
cpplink   := $(CXX)
endif

math_lib    := -lm

# test submodules exist (they don't exist for dist_rpm, dist_dpkg targets)
test_makefile = $(shell if [ -f ./$(1)/GNUmakefile ] ; then echo ./$(1) ; \
                        elif [ -f ../$(1)/GNUmakefile ] ; then echo ../$(1) ; fi)
md_home     := $(call test_makefile,raimd)
dec_home    := $(call test_makefile,libdecnumber)
kv_home     := $(call test_makefile,raikv)
ds_home     := $(call test_makefile,raids)
lc_home     := $(call test_makefile,linecook)
h3_home     := $(call test_makefile,h3)
rdb_home    := $(call test_makefile,rdbparser)
pgm_home    := $(call test_makefile,openpgm)
sassrv_home := $(call test_makefile,sassrv)
natsmd_home := $(call test_makefile,natsmd)
lzf_home    := $(call test_makefile,lzf)

ifeq (,$(dec_home))
dec_home    := $(call test_makefile,$(md_home)/libdecnumber)
endif
ifeq (,$(h3_home))
h3_home     := $(call test_makefile,$(ds_home)/h3)
endif
ifeq (,$(rdb_home))
rdb_home    := $(call test_makefile,$(ds_home)/rdbparser)
endif
ifeq (,$(lzf_home))
lzf_home    := $(call test_makefile,$(rdb_home)/lzf)
endif

lnk_lib     := -Wl,--push-state -Wl,-Bstatic
lnk_lib     += $(libd)/libraims.a
dlnk_lib    :=
lnk_dep     := $(libd)/libraims.a
dlnk_dep    :=

ifneq (,$(ds_home))
ds_lib      := $(ds_home)/$(libd)/libraids.a
ds_dll      := $(ds_home)/$(libd)/libraids.$(dll)
lnk_lib     += $(ds_lib)
lnk_dep     += $(ds_lib)
dlnk_lib    += -L$(ds_home)/$(libd) -lraids
dlnk_dep    += $(ds_dll)
rpath1       = ,-rpath,$(pwd)/$(ds_home)/$(libd)
ds_includes  = -I$(ds_home)/include
else
lnk_lib     += -lraids
dlnk_lib    += -lraids
endif

ifneq (,$(md_home))
md_lib      := $(md_home)/$(libd)/libraimd.a
md_dll      := $(md_home)/$(libd)/libraimd.$(dll)
lnk_lib     += $(md_lib)
lnk_dep     += $(md_lib)
dlnk_lib    += -L$(md_home)/$(libd) -lraimd
dlnk_dep    += $(md_dll)
rpath2       = ,-rpath,$(pwd)/$(md_home)/$(libd)
includes    += -I$(md_home)/include
else
lnk_lib     += -lraimd
dlnk_lib    += -lraimd
endif

ifneq (,$(dec_home))
dec_lib     := $(dec_home)/$(libd)/libdecnumber.a
dec_dll     := $(dec_home)/$(libd)/libdecnumber.$(dll)
lnk_lib     += $(dec_lib)
lnk_dep     += $(dec_lib)
dlnk_lib    += -L$(dec_home)/$(libd) -ldecnumber
dlnk_dep    += $(dec_dll)
rpath3       = ,-rpath,$(pwd)/$(dec_home)/$(libd)
dec_includes = -I$(dec_home)/include
else
lnk_lib     += -ldecnumber
dlnk_lib    += -ldecnumber
endif

ifneq (,$(lc_home))
lc_lib      := $(lc_home)/$(libd)/liblinecook.a
lc_dll      := $(lc_home)/$(libd)/liblinecook.$(dll)
lnk_lib     += $(lc_lib)
lnk_dep     += $(lc_lib)
dlnk_lib    += -L$(lc_home)/$(libd) -llinecook
dlnk_dep    += $(lc_dll)
rpath4       = ,-rpath,$(pwd)/$(lc_home)/$(libd)
lc_includes  = -I$(lc_home)/include
else
lnk_lib     += -llinecook
dlnk_lib    += -llinecook
endif

ifneq (,$(h3_home))
h3_lib      := $(h3_home)/$(libd)/libh3.a
h3_dll      := $(h3_home)/$(libd)/libh3.$(dll)
lnk_lib     += $(h3_lib)
lnk_dep     += $(h3_lib)
dlnk_lib    += -L$(h3_home)/$(libd) -lh3
dlnk_dep    += $(h3_dll)
rpath5       = ,-rpath,$(pwd)/$(h3_home)/$(libd)
h3_includes  = -I$(h3_home)/src/h3lib/include
else
lnk_lib     += -lh3
dlnk_lib    += -lh3
endif

ifneq (,$(rdb_home))
rdb_lib     := $(rdb_home)/$(libd)/librdbparser.a
rdb_dll     := $(rdb_home)/$(libd)/librdbparser.$(dll)
lnk_lib     += $(rdb_lib)
lnk_dep     += $(rdb_lib)
dlnk_lib    += -L$(rdb_home)/$(libd) -lrdbparser
dlnk_dep    += $(rdb_dll)
rpath6       = ,-rpath,$(pwd)/$(rdb_home)/$(libd)
rdb_includes = -I$(rdb_home)/include
else
lnk_lib     += -lrdbparser
dlnk_lib    += -lrdbparser
endif

ifneq (,$(kv_home))
kv_lib      := $(kv_home)/$(libd)/libraikv.a
kv_dll      := $(kv_home)/$(libd)/libraikv.$(dll)
lnk_lib     += $(kv_lib)
lnk_dep     += $(kv_lib)
dlnk_lib    += -L$(kv_home)/$(libd) -lraikv
dlnk_dep    += $(kv_dll)
rpath7       = ,-rpath,$(pwd)/$(kv_home)/$(libd)
includes    += -I$(kv_home)/include
else
lnk_lib     += -lraikv
dlnk_lib    += -lraikv
endif

ifneq (,$(pgm_home))
pgm_lib     := $(pgm_home)/$(libd)/libopenpgm_st.a
pgm_dll     := $(pgm_home)/$(libd)/libopenpgm_st.$(dll)
lnk_lib     += $(pgm_lib)
lnk_dep     += $(pgm_lib)
dlnk_lib    += -L$(pgm_home)/$(libd) -lopenpgm_st
dlnk_dep    += $(pgm_dll)
rpath8       = ,-rpath,$(pwd)/$(pgm_home)/$(libd)
pgm_includes = -I$(pgm_home)/openpgm/pgm/include
else
lnk_lib     += -lopenpgm_st
dlnk_lib    += -lopenpgm_st
endif

ifneq (,$(sassrv_home))
sassrv_lib  := $(sassrv_home)/$(libd)/libsassrv.a
sassrv_dll  := $(sassrv_home)/$(libd)/libsassrv.$(dll)
lnk_lib     += $(sassrv_lib)
lnk_dep     += $(sassrv_lib)
dlnk_lib    += -L$(sassrv_home)/$(libd) -lsassrv
dlnk_dep    += $(sassrv_dll)
rpath9       = ,-rpath,$(pwd)/$(sassrv_home)/$(libd)
sassrv_includes = -I$(sassrv_home)/include
else
lnk_lib     += -lsassrv
dlnk_lib    += -lsassrv
endif

ifneq (,$(natsmd_home))
natsmd_lib  := $(natsmd_home)/$(libd)/libnatsmd.a
natsmd_dll  := $(natsmd_home)/$(libd)/libnatsmd.$(dll)
lnk_lib     += $(natsmd_lib)
lnk_dep     += $(natsmd_lib)
dlnk_lib    += -L$(natsmd_home)/$(libd) -lnatsmd
dlnk_dep    += $(natsmd_dll)
rpath10      = ,-rpath,$(pwd)/$(natsmd_home)/$(libd)
natsmd_includes = -I$(natsmd_home)/include
else
lnk_lib     += -lnatsmd
dlnk_lib    += -lnatsmd
endif

lnk_lib += -Wl,--pop-state

ifneq (,$(lzf_home))
lzf_lib     := $(lzf_home)/$(libd)/liblzf.a
lzf_dll     := $(lzf_home)/$(libd)/liblzf.$(dll)
lnk_lib     += $(lzf_lib)
lnk_dep     += $(lzf_lib)
dlnk_lib    += -L$(lzf_home)/$(libd) -llzf
dlnk_dep    += $(lzf_dll)
rpath11      = ,-rpath,$(pwd)/$(lzf_home)/$(libd)
lzf_includes = -I$(lzf_home)/include
else
lnk_lib     += -llzf
dlnk_lib    += -llzf
includes    += -I/usr/include/liblzf
endif

rpath := -Wl,-rpath,$(pwd)/$(libd)$(rpath1)$(rpath2)$(rpath3)$(rpath4)$(rpath5)$(rpath6)$(rpath7)$(rpath8)$(rpath9)$(rpath10)$(rpath11)

.PHONY: everything
everything: $(kv_lib) $(dec_lib) $(lzf_lib) $(md_lib) $(lc_lib) $(h3_lib) $(rdb_lib) $(ds_lib) $(pgm_lib) $(sassrv_lib) $(natsmd_lib) all

clean_subs :=
dlnk_dll_depend :=
dlnk_lib_depend :=

# build submodules if have them
ifneq (,$(kv_home))
$(kv_lib) $(kv_dll):
	$(MAKE) -C $(kv_home)
.PHONY: clean_kv
clean_kv:
	$(MAKE) -C $(kv_home) clean
clean_subs += clean_kv
endif
ifneq (,$(dec_home))
$(dec_lib) $(dec_dll):
	$(MAKE) -C $(dec_home)
.PHONY: clean_dec
clean_dec:
	$(MAKE) -C $(dec_home) clean
clean_subs += clean_dec
endif
ifneq (,$(md_home))
$(md_lib) $(md_dll):
	$(MAKE) -C $(md_home)
.PHONY: clean_md
clean_md:
	$(MAKE) -C $(md_home) clean
clean_subs += clean_md
endif
ifneq (,$(ds_home))
$(ds_lib) $(ds_dll):
	$(MAKE) -C $(ds_home)
.PHONY: clean_ds
clean_ds:
	$(MAKE) -C $(ds_home) clean
clean_subs += clean_ds
endif
ifneq (,$(lc_home))
$(lc_lib) $(lc_dll):
	$(MAKE) -C $(lc_home)
.PHONY: clean_lc
clean_lc:
	$(MAKE) -C $(lc_home) clean
clean_subs += clean_lc
endif
ifneq (,$(h3_home))
$(h3_lib) $(h3_dll):
	$(MAKE) -C $(h3_home)
.PHONY: clean_h3
clean_h3:
	$(MAKE) -C $(h3_home) clean
clean_subs += clean_h3
endif
ifneq (,$(rdb_home))
$(rdb_lib) $(rdb_dll):
	$(MAKE) -C $(rdb_home)
.PHONY: clean_rdb
clean_rdb:
	$(MAKE) -C $(rdb_home) clean
clean_subs += clean_rdb
endif
ifneq (,$(pgm_home))
$(pgm_lib) $(pgm_dll):
	$(MAKE) -C $(pgm_home)
.PHONY: clean_pgm
clean_pgm:
	$(MAKE) -C $(pgm_home) clean
clean_subs += clean_pgm
endif
ifneq (,$(sassrv_home))
$(sassrv_lib) $(sassrv_dll):
	$(MAKE) -C $(sassrv_home)
.PHONY: clean_sassrv
clean_sassrv:
	$(MAKE) -C $(sassrv_home) clean
clean_subs += clean_sassrv
endif
ifneq (,$(natsmd_home))
$(natsmd_lib) $(natsmd_dll):
	$(MAKE) -C $(natsmd_home)
.PHONY: clean_natsmd
clean_natsmd:
	$(MAKE) -C $(natsmd_home) clean
clean_subs += clean_natsmd
endif
ifneq (,$(lzf_home))
$(lzf_lib) $(lzf_dll):
	$(MAKE) -C $(lzf_home)
.PHONY: clean_lzf
clean_lzf:
	$(MAKE) -C $(lzf_home) clean
clean_subs += clean_lzf
endif

# copr/fedora build (with version env vars)
# copr uses this to generate a source rpm with the srpm target
-include .copr/Makefile

# debian build (debuild)
# target for building installable deb: dist_dpkg
-include deb/Makefile

# targets filled in below
all_exes    :=
all_libs    :=
all_dlls    :=
all_depends :=
gen_files   :=

session_includes            := $(ds_includes)
heartbeat_includes          := $(sassrv_includes)
ev_rv_transport_includes    := $(sassrv_includes) $(ds_includes)
ev_nats_transport_includes  := $(natsmd_includes)
transport_includes          := $(pgm_includes) $(natsmd_includes) $(sassrv_includes) $(ds_includes)
session_tport_includes      := $(pgm_includes) $(natsmd_includes) $(sassrv_includes) $(ds_includes)
conn_mgr_includes           := $(pgm_includes) $(natsmd_includes) $(sassrv_includes) $(ds_includes)
ev_pgm_transport_includes   := $(pgm_includes)
pgm_sock_includes           := $(pgm_includes)
console_includes            := $(natsmd_includes) $(sassrv_includes) $(ds_includes) $(lc_includes)
ev_telnet_includes          := $(ds_includes) $(lc_includes)
ev_web_includes             := $(ds_includes)
ev_redis_transport_includes := $(ds_includes)
server_includes             := $(ds_includes) $(lc_includes)

session_defines := -DMS_VER=$(ver_build)
libraims_files := session user_db heartbeat auth peer link_state adjacency \
                  config user msg sub pat transport session_tport \
		  conn_mgr console stats adj_test gen_config \
		  crypt poly1305 ec25519 ed25519 sha512 aes \
		  ev_tcp_aes ev_tcp_transport ev_pgm_transport pgm_sock \
		  ev_inbox_transport ev_telnet ev_web ev_rv_transport \
		  ev_nats_transport ev_redis_transport ev_name_svc
libraims_files := $(libraims_files)
libraims_cfile := $(addprefix src/, $(addsuffix .cpp, $(libraims_files)))
libraims_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(libraims_files)))
libraims_dbjs  := $(addprefix $(objd)/, $(addsuffix .fpic.o, $(libraims_files)))
libraims_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(libraims_files))) \
                   $(addprefix $(dependd)/, $(addsuffix .fpic.d, $(libraims_files)))
libraims_dlnk  := $(dlnk_lib)
libraims_spec  := $(version)-$(build_num)_$(git_hash)
libraims_ver   := $(major_num).$(minor_num)

$(libd)/libraims.a: $(libraims_objs)
$(libd)/libraims.$(dll): $(libraims_dbjs) $(dlnk_dep)

all_libs    += $(libd)/libraims.a $(libd)/libraims.$(dll)
all_depends += $(libraims_deps)

web_files := $(wildcard web/*)
include/raims/ev_web_tar.h: $(web_files)
	echo "static const uint8_t ev_web_tar_data[] = {" > $@
	tar cf - $(web_files) | \
	od -v -t x1 | \
	cut --output-delimiter ',0x' -b 8,9-10,12-13,15-16,18-19,21-22,24-25,27-28,30-31,33-34,36-37,39-40,42-43,45-46,48-49,51-52,54-55 | \
	tail -c +3 >> $@
	echo "};" >> $@

gen_files += include/raims/ev_web_tar.h

ms_gen_key_files := gen_key
ms_gen_key_cfile := src/gen_key.cpp
ms_gen_key_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ms_gen_key_files)))
ms_gen_key_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ms_gen_key_files)))
ms_gen_key_libs  :=
ms_gen_key_lnk   := $(lnk_lib)

$(bind)/ms_gen_key$(exe): $(ms_gen_key_objs) $(ms_gen_key_libs) $(lnk_dep)

all_exes    += $(bind)/ms_gen_key$(exe)
all_depends += $(ms_gen_key_deps)

kdftest_files := kdftest
kdftest_cfile := test/kdftest.cpp
kdftest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(kdftest_files)))
kdftest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(kdftest_files)))
kdftest_libs  :=
kdftest_lnk   := $(lnk_lib)

$(bind)/kdftest$(exe): $(kdftest_objs) $(kdftest_libs) $(lnk_dep)

all_exes    += $(bind)/kdftest$(exe)
all_depends += $(kdftest_deps)

mactest_files := mactest
mactest_cfile := test/mactest.cpp
mactest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(mactest_files)))
mactest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(mactest_files)))
mactest_libs  :=
mactest_lnk   := $(lnk_lib)

$(bind)/mactest$(exe): $(mactest_objs) $(mactest_libs) $(lnk_dep)

all_exes    += $(bind)/mactest$(exe)
all_depends += $(mactest_deps)

polytest_files := polytest
polytest_cfile := test/polytest.cpp
polytest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(polytest_files)))
polytest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(polytest_files)))
polytest_libs  :=
polytest_lnk   := $(lnk_lib)

$(bind)/polytest$(exe): $(polytest_objs) $(polytest_libs) $(lnk_dep)

all_exes    += $(bind)/polytest$(exe)
all_depends += $(polytest_deps)

#ecdhtest_files := ecdhtest
#ecdhtest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ecdhtest_files)))
#ecdhtest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ecdhtest_files)))
#ecdhtest_libs  :=
#ecdhtest_lnk   := $(lnk_lib)

#$(bind)/ecdhtest$(exe): $(ecdhtest_objs) $(ecdhtest_libs) $(lnk_dep)

#all_exes    += $(bind)/ecdhtest$(exe)
#all_depends += $(ecdhtest_deps)

curvetest_files := curvetest
curvetest_cfile := test/curvetest.cpp
curvetest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(curvetest_files)))
curvetest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(curvetest_files)))
curvetest_libs  :=
curvetest_lnk   := $(lnk_lib)

$(bind)/curvetest$(exe): $(curvetest_objs) $(curvetest_libs) $(lnk_dep)

all_exes    += $(bind)/curvetest$(exe)
all_depends += $(curvetest_deps)

dsatest_files := dsatest
dsatest_cfile := test/dsatest.cpp
dsatest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(dsatest_files)))
dsatest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(dsatest_files)))
dsatest_libs  :=
dsatest_lnk   := $(lnk_lib)

$(bind)/dsatest$(exe): $(dsatest_objs) $(dsatest_libs) $(lnk_dep)

all_exes    += $(bind)/dsatest$(exe)
all_depends += $(dsatest_deps)

sigtest_files := sigtest
sigtest_cfile := test/sigtest.cpp
sigtest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(sigtest_files)))
sigtest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(sigtest_files)))
sigtest_libs  :=
sigtest_lnk   := $(lnk_lib)

$(bind)/sigtest$(exe): $(sigtest_objs) $(sigtest_libs) $(lnk_dep)

all_exes    += $(bind)/sigtest$(exe)
all_depends += $(sigtest_deps)

shatest_files := shatest
shatest_cfile := test/shatest.cpp
shatest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(shatest_files)))
shatest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(shatest_files)))
shatest_libs  :=
shatest_lnk   := $(lnk_lib)

$(bind)/shatest$(exe): $(shatest_objs) $(shatest_libs) $(lnk_dep)

all_exes    += $(bind)/shatest$(exe)
all_depends += $(shatest_deps)

aestest_files := aestest
aestest_cfile := test/aestest.cpp
aestest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(aestest_files)))
aestest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(aestest_files)))
aestest_libs  :=
aestest_lnk   := $(lnk_lib)

$(bind)/aestest$(exe): $(aestest_objs) $(aestest_libs) $(lnk_dep)

all_exes    += $(bind)/aestest$(exe)
all_depends += $(aestest_deps)

matchtest_files := matchtest
matchtest_cfile := test/matchtest.cpp
matchtest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(matchtest_files)))
matchtest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(matchtest_files)))
matchtest_libs  :=
matchtest_lnk   := $(lnk_lib)

$(bind)/matchtest$(exe): $(matchtest_objs) $(matchtest_libs) $(lnk_dep)

all_exes    += $(bind)/matchtest$(exe)
all_depends += $(matchtest_deps)

ms_test_adj_files := test_adj
ms_test_adj_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ms_test_adj_files)))
ms_test_adj_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ms_test_adj_files)))
ms_test_adj_libs  :=
ms_test_adj_lnk   := $(lnk_lib)

$(bind)/ms_test_adj$(exe): $(ms_test_adj_objs) $(ms_test_adj_libs) $(lnk_dep)

all_exes    += $(bind)/ms_test_adj$(exe)
all_depends += $(ms_test_adj_deps)

parse_config_files := parse_config
parse_config_cfile := test/parse_config.cpp
parse_config_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(parse_config_files)))
parse_config_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(parse_config_files)))
parse_config_libs  :=
parse_config_lnk   := $(lnk_lib)

$(bind)/parse_config$(exe): $(parse_config_objs) $(parse_config_libs) $(lnk_dep)

all_exes    += $(bind)/parse_config$(exe)
all_depends += $(parse_config_deps)

test_tcp_aes_files := test_tcp_aes
test_tcp_aes_cfile := test/test_tcp_aes.cpp
test_tcp_aes_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(test_tcp_aes_files)))
test_tcp_aes_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(test_tcp_aes_files)))
test_tcp_aes_libs  :=
test_tcp_aes_lnk   := $(lnk_lib)

$(bind)/test_tcp_aes$(exe): $(test_tcp_aes_objs) $(test_tcp_aes_libs) $(lnk_dep)

all_exes    += $(bind)/test_conn$(exe)
all_depends += $(test_conn_deps)

test_conn_files := test_conn
test_conn_cfile := test/test_conn.cpp
test_conn_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(test_conn_files)))
test_conn_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(test_conn_files)))
test_conn_libs  :=
test_conn_lnk   := $(lnk_lib)

$(bind)/test_conn$(exe): $(test_conn_objs) $(test_conn_libs) $(lnk_dep)

all_exes    += $(bind)/test_conn$(exe)
all_depends += $(test_conn_deps)

parse_pcap_files := parse_pcap
parse_pcap_cfile := test/parse_pcap.cpp
parse_pcap_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(parse_pcap_files)))
parse_pcap_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(parse_pcap_files)))
parse_pcap_libs  :=
parse_pcap_lnk   := $(lnk_lib) -lpcap

$(bind)/parse_pcap$(exe): $(parse_pcap_objs) $(parse_pcap_libs) $(lnk_dep)

#all_exes    += $(bind)/parse_pcap$(exe)
#all_depends += $(parse_pcap_deps)

ms_server_files := server
ms_server_cfile := src/server.cpp
ms_server_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ms_server_files)))
ms_server_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ms_server_files)))
ms_server_libs  :=
ms_server_lnk   := $(lnk_lib)

$(bind)/ms_server$(exe): $(ms_server_objs) $(ms_server_libs) $(lnk_dep)

all_exes    += $(bind)/ms_server$(exe)
all_depends += $(ms_server_deps)

all_dirs := $(bind) $(libd) $(objd) $(dependd)

ifeq ($(have_asciidoctor),true)
doc/index.html: $(wildcard doc/*.adoc)
	asciidoctor -b html5 doc/index.adoc
gen_files += doc/index.html
endif

# the default targets
.PHONY: all
all: $(gen_files) $(all_libs) $(all_dlls) $(all_exes) cmake

.PHONY: cmake
cmake: CMakeLists.txt

.ONESHELL: CMakeLists.txt
CMakeLists.txt: .copr/Makefile
	@cat <<'EOF' > $@
	cmake_minimum_required (VERSION 3.9.0)
	if (POLICY CMP0111)
	  cmake_policy(SET CMP0111 OLD)
	endif ()
	project (raims)
	include_directories (
	  include
	  $${CMAKE_SOURCE_DIR}/raimd/include
	  $${CMAKE_SOURCE_DIR}/raikv/include
	  $${CMAKE_SOURCE_DIR}/raids/include
	  $${CMAKE_SOURCE_DIR}/sassrv/include
	  $${CMAKE_SOURCE_DIR}/natsmd/include
	  $${CMAKE_SOURCE_DIR}/libdecnumber/include
	  $${CMAKE_SOURCE_DIR}/raimd/libdecnumber/include
	  $${CMAKE_SOURCE_DIR}/linecook/include
	  $${CMAKE_SOURCE_DIR}/pcre2
	  $${CMAKE_SOURCE_DIR}/openpgm/openpgm/pgm/include
	)
	if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	  add_definitions(/DPCRE2_STATIC)
	  if ($$<CONFIG:Release>)
	    add_compile_options (/arch:AVX2 /GL /std:c11 /wd5105)
	  else ()
	    add_compile_options (/arch:AVX2 /std:c11 /wd5105)
	  endif ()
	  if (NOT TARGET pcre2-8-static)
	    add_library (pcre2-8-static STATIC IMPORTED)
	    set_property (TARGET pcre2-8-static PROPERTY IMPORTED_LOCATION_DEBUG ../pcre2/build/Debug/pcre2-8-staticd.lib)
	    set_property (TARGET pcre2-8-static PROPERTY IMPORTED_LOCATION_RELEASE ../pcre2/build/Release/pcre2-8-static.lib)
	    add_library (pcre2-32-static STATIC IMPORTED)
	    set_property (TARGET pcre2-32-static PROPERTY IMPORTED_LOCATION_DEBUG ../pcre2/build/Debug/pcre2-32-staticd.lib)
	    set_property (TARGET pcre2-32-static PROPERTY IMPORTED_LOCATION_RELEASE ../pcre2/build/Release/pcre2-32-static.lib)
	    include_directories (../pcre2/build)
	  else ()
	    include_directories ($${CMAKE_BINARY_DIR}/pcre2)
	  endif ()
	  set (pcre2lib pcre2-8-static pcre2-32-static)
	  if (NOT TARGET raids)
	    add_library (raids STATIC IMPORTED)
	    set_property (TARGET raids PROPERTY IMPORTED_LOCATION_DEBUG ../raids/build/Debug/raids.lib)
	    set_property (TARGET raids PROPERTY IMPORTED_LOCATION_RELEASE ../raids/build/Release/raids.lib)
	  endif ()
	  if (NOT TARGET raikv)
	    add_library (raikv STATIC IMPORTED)
	    set_property (TARGET raikv PROPERTY IMPORTED_LOCATION_DEBUG ../raikv/build/Debug/raikv.lib)
	    set_property (TARGET raikv PROPERTY IMPORTED_LOCATION_RELEASE ../raikv/build/Release/raikv.lib)
	  endif ()
	  if (NOT TARGET raimd)
	    add_library (raimd STATIC IMPORTED)
	    set_property (TARGET raimd PROPERTY IMPORTED_LOCATION_DEBUG ../raimd/build/Debug/raimd.lib)
	    set_property (TARGET raimd PROPERTY IMPORTED_LOCATION_RELEASE ../raimd/build/Release/raimd.lib)
	  endif ()
	  if (NOT TARGET decnumber)
	    add_library (decnumber STATIC IMPORTED)
	    set_property (TARGET decnumber PROPERTY IMPORTED_LOCATION_DEBUG ../raimd/libdecnumber/build/Debug/decnumber.lib)
	    set_property (TARGET decnumber PROPERTY IMPORTED_LOCATION_RELEASE ../raimd/libdecnumber/build/Release/decnumber.lib)
	  endif ()
	  if (NOT TARGET rdbparser)
	    add_library (rdbparser STATIC IMPORTED)
	    set_property (TARGET rdbparser PROPERTY IMPORTED_LOCATION_DEBUG ../raids/rdbparser/build/Debug/rdbparser.lib)
	    set_property (TARGET rdbparser PROPERTY IMPORTED_LOCATION_RELEASE ../raids/rdbparser/build/Release/rdbparser.lib)
	  endif ()
	  if (NOT TARGET linecook)
	    add_library (linecook STATIC IMPORTED)
	    set_property (TARGET linecook PROPERTY IMPORTED_LOCATION_DEBUG ../linecook/build/Debug/linecook.lib)
	    set_property (TARGET linecook PROPERTY IMPORTED_LOCATION_RELEASE ../linecook/build/Release/linecook.lib)
	  endif ()
	  if (NOT TARGET h3)
	    add_library (h3 STATIC IMPORTED)
	    set_property (TARGET h3 PROPERTY IMPORTED_LOCATION_DEBUG ../raids/h3/build/bin/Debug/h3.lib)
	    set_property (TARGET h3 PROPERTY IMPORTED_LOCATION_RELEASE ../raids/h3/build/bin/Release/h3.lib)
	  else ()
	    include_directories ($${CMAKE_BINARY_DIR}/src/h3lib/include)
	  endif ()
	  if (NOT TARGET lzf)
	    add_library (lzf STATIC IMPORTED)
	    set_property (TARGET lzf PROPERTY IMPORTED_LOCATION_DEBUG ../raids/rdbparser/lzf/build/Debug/lzf.lib)
	    set_property (TARGET lzf PROPERTY IMPORTED_LOCATION_RELEASE ../raids/rdbparser/lzf/build/Release/lzf.lib)
	  endif ()
	  if (NOT TARGET openpgm_st)
	    add_library (openpgm_st STATIC IMPORTED)
	    set_property (TARGET openpgm_st PROPERTY IMPORTED_LOCATION_DEBUG ../openpgm/build/Debug/openpgm_st.lib)
	    set_property (TARGET openpgm_st PROPERTY IMPORTED_LOCATION_RELEASE ../openpgm/build/Release/openpgm_st.lib)
	  endif ()
	  if (NOT TARGET sassrv)
	    add_library (sassrv STATIC IMPORTED)
	    set_property (TARGET sassrv PROPERTY IMPORTED_LOCATION_DEBUG ../sassrv/build/Debug/sassrv.lib)
	    set_property (TARGET sassrv PROPERTY IMPORTED_LOCATION_RELEASE ../sassrv/build/Release/sassrv.lib)
	  endif ()
	  if (NOT TARGET natsmd)
	    add_library (natsmd STATIC IMPORTED)
	    set_property (TARGET natsmd PROPERTY IMPORTED_LOCATION_DEBUG ../natsmd/build/Debug/natsmd.lib)
	    set_property (TARGET natsmd PROPERTY IMPORTED_LOCATION_RELEASE ../natsmd/build/Release/natsmd.lib)
	  endif ()
	else ()
	  add_compile_options ($(cflags))
	  if (TARGET pcre2-8-static)
	    include_directories ($${CMAKE_BINARY_DIR}/pcre2)
	    set (pcre2lib pcre2-8-static pcre2-32-static)
	  else ()
	    set (pcre2lib -lpcre2-32 -lpcre2-8)
	  endif ()
	  if (NOT TARGET raids)
	    add_library (raids STATIC IMPORTED)
	    set_property (TARGET raids PROPERTY IMPORTED_LOCATION ../raids/build/libraids.a)
	  endif ()
	  if (NOT TARGET raikv)
	    add_library (raikv STATIC IMPORTED)
	    set_property (TARGET raikv PROPERTY IMPORTED_LOCATION ../raikv/build/libraikv.a)
	  endif ()
	  if (NOT TARGET raimd)
	    add_library (raimd STATIC IMPORTED)
	    set_property (TARGET raimd PROPERTY IMPORTED_LOCATION ../raimd/build/libraimd.a)
	  endif ()
	  if (NOT TARGET decnumber)
	    add_library (decnumber STATIC IMPORTED)
	    set_property (TARGET decnumber PROPERTY IMPORTED_LOCATION ../raimd/libdecnumber/build/libdecnumber.a)
	  endif ()
	  if (NOT TARGET rdbparser)
	    add_library (rdbparser STATIC IMPORTED)
	    set_property (TARGET rdbparser PROPERTY IMPORTED_LOCATION ../raids/rdbparser/build/librdbparser.a)
	  endif ()
	  if (NOT TARGET linecook)
	    add_library (linecook STATIC IMPORTED)
	    set_property (TARGET linecook PROPERTY IMPORTED_LOCATION ../linecook/build/liblinecook.a)
	  endif ()
	  if (NOT TARGET h3)
	    add_library (h3 STATIC IMPORTED)
	    set_property (TARGET h3 PROPERTY IMPORTED_LOCATION ../raids/h3/build/lib/libh3.a)
	  else ()
	    include_directories ($${CMAKE_BINARY_DIR}/src/h3lib/include)
	  endif ()
	  if (NOT TARGET lzf)
	    add_library (lzf STATIC IMPORTED)
	    set_property (TARGET lzf PROPERTY IMPORTED_LOCATION ../raids/rdbparser/lzf/build/liblzf.a)
	  endif ()
	  if (NOT TARGET openpgm_st)
	    add_library (openpgm_st STATIC IMPORTED)
	    set_property (TARGET openpgm_st PROPERTY IMPORTED_LOCATION ../openpgm/build/libopenpgm_st.a)
	  endif ()
	  if (NOT TARGET sassrv)
	    add_library (sassrv STATIC IMPORTED)
	    set_property (TARGET sassrv PROPERTY IMPORTED_LOCATION ../sassrv/build/libsassrv.a)
	  endif ()
	  if (NOT TARGET natsmd)
	    add_library (natsmd STATIC IMPORTED)
	    set_property (TARGET natsmd PROPERTY IMPORTED_LOCATION ../natsmd/build/libnatsmd.a)
	  endif ()
	endif ()
	if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	  set (ex_lib ws2_32)
	else ()
	  set (ex_lib -lssl -lcrypto -lcares -lpthread -lrt)
	endif ()
	add_library (raims STATIC $(libraims_cfile))
	link_libraries (raims raids raikv raimd natsmd sassrv decnumber rdbparser linecook h3 lzf openpgm_st $${pcre2lib} $${ex_lib})
	add_definitions(-DMS_VER=$(ver_build))
	add_executable (ms_server $(ms_server_cfile))
	add_executable (ms_gen_key $(ms_gen_key_cfile))
	add_executable (ms_test_adj $(ms_test_adj_cfile))
	add_executable (kdftest $(kdftest_cfile))
	add_executable (mactest $(mactest_cfile))
	add_executable (polytest $(polytest_cfile))
	add_executable (curvetest $(curvetest_cfile))
	add_executable (dsatest $(dsatest_cfile))
	add_executable (shatest $(shatest_cfile))
	add_executable (aestest $(aestest_cfile))
	add_executable (parse_config $(parse_config_cfile))
	EOF


.PHONY: dnf_depend
dnf_depend:
	sudo dnf -y install make gcc-c++ git redhat-lsb openssl-devel pcre2-devel chrpath c-ares-devel

.PHONY: yum_depend
yum_depend:
	sudo yum -y install make gcc-c++ git redhat-lsb openssl-devel pcre2-devel chrpath c-ares-devel

.PHONY: deb_depend
deb_depend:
	sudo apt-get install -y install make g++ gcc devscripts libpcre2-dev chrpath git lsb-release libssl-dev c-ares-dev

# create directories
$(dependd):
	@mkdir -p $(all_dirs)

# remove target bins, objs, depends
.PHONY: clean
clean: $(clean_subs)
	rm -r -f $(bind) $(libd) $(objd) $(dependd)
	if [ "$(build_dir)" != "." ] ; then rmdir $(build_dir) ; fi

.PHONY: clean_dist
clean_dist:
	rm -rf dpkgbuild rpmbuild

.PHONY: clean_all
clean_all: clean clean_dist

# force a remake of depend using 'make -B depend'
.PHONY: depend
depend: $(dependd)/depend.make

$(dependd)/depend.make: $(dependd) $(all_depends)
	@echo "# depend file" > $(dependd)/depend.make
	@cat $(all_depends) >> $(dependd)/depend.make

ifeq (SunOS,$(lsb_dist))
remove_rpath = rpath -r
else
ifeq (Darwin,$(lsb_dist))
remove_rpath = true
else
remove_rpath = chrpath -d
endif
endif

.PHONY: dist_bins
dist_bins: $(all_libs) $(bind)/ms_server $(bind)/ms_gen_key $(bind)/ms_test_adj
	$(remove_rpath) $(libd)/libraims.$(dll)
	$(remove_rpath) $(bind)/ms_server$(exe)
	$(remove_rpath) $(bind)/ms_gen_key$(exe)
	$(remove_rpath) $(bind)/ms_test_adj$(exe)

.PHONY: dist_rpm
dist_rpm: srpm
	( cd rpmbuild && rpmbuild --define "-topdir `pwd`" -ba SPECS/raims.spec )

# dependencies made by 'make depend'
-include $(dependd)/depend.make

ifeq ($(DESTDIR),)
# 'sudo make install' puts things in /usr/local/lib, /usr/local/include
install_prefix = /usr/local
else
# debuild uses DESTDIR to put things into debian/raims/usr
install_prefix = $(DESTDIR)/usr
endif

install: dist_bins
	install -d $(install_prefix)/lib $(install_prefix)/bin
	install -d $(install_prefix)/include/raims
	for f in $(libd)/libraims.* ; do \
	if [ -h $$f ] ; then \
	cp -a $$f $(install_prefix)/lib ; \
	else \
	install $$f $(install_prefix)/lib ; \
	fi ; \
	done
	install -m 755 $(bind)/ms_server$(exe) $(install_prefix)/bin
	install -m 755 $(bind)/ms_gen_key$(exe) $(install_prefix)/bin
	install -m 755 $(bind)/ms_test_adj$(exe) $(install_prefix)/bin
	install -m 644 include/raims/*.h $(install_prefix)/include/raims

$(objd)/%.o: src/%.cpp
	$(cpp) $(cflags) $(cppflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.o: src/%.c
	$(cc) $(cflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.fpic.o: src/%.cpp
	$(cpp) $(cflags) $(fpicflags) $(cppflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.fpic.o: src/%.c
	$(cc) $(cflags) $(fpicflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.o: test/%.cpp
	$(cpp) $(cflags) $(cppflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.o: test/%.c
	$(cc) $(cflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(libd)/%.a:
	ar rc $@ $($(*)_objs)

ifeq (Darwin,$(lsb_dist))
$(libd)/%.dylib:
	$(cpplink) -dynamiclib $(cflags) $(lflags) -o $@.$($(*)_dylib).dylib -current_version $($(*)_dylib) -compatibility_version $($(*)_ver) $($(*)_dbjs) $($(*)_dlnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib) && \
	cd $(libd) && ln -f -s $(@F).$($(*)_dylib).dylib $(@F).$($(*)_ver).dylib && ln -f -s $(@F).$($(*)_ver).dylib $(@F)
else
$(libd)/%.$(dll):
	$(cpplink) $(soflag) $(rpath) $(cflags) $(lflags) -o $@.$($(*)_spec) -Wl,-soname=$(@F).$($(*)_ver) $($(*)_dbjs) $($(*)_dlnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib) && \
	cd $(libd) && ln -f -s $(@F).$($(*)_spec) $(@F).$($(*)_ver) && ln -f -s $(@F).$($(*)_ver) $(@F)
endif

$(bind)/%$(exe):
	$(cpplink) $(cflags) $(lflags) $(rpath) -o $@ $($(*)_objs) -L$(libd) $($(*)_lnk) $(cpp_lnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib)

$(dependd)/%.d: src/%.cpp
	$(cpp) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

$(dependd)/%.d: src/%.c
	$(cc) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

$(dependd)/%.fpic.d: src/%.cpp
	$(cpp) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).fpic.o -MF $@

$(dependd)/%.fpic.d: src/%.c
	$(cc) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).fpic.o -MF $@

$(dependd)/%.d: test/%.cpp
	$(cpp) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

$(dependd)/%.d: test/%.c
	$(cc) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

