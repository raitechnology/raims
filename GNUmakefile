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
  default_cflags += -fsanitize=address
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
gcc_wflags  := -Wall -Wextra
#-Werror
# if windows cross compile
ifeq (true,$(mingw))
dll         := dll
exe         := .exe
soflag      := -shared -Wl,--subsystem,windows
fpicflags   := -fPIC -DMS_SHARED
sock_lib    := -lcares -lssl -lcrypto -lws2_32 -lpsapi -lwinmm -liphlpapi
dynlink_lib := -lpcre2-8 -lpcre2-32 -lz
NO_STL      := 1
else
dll         := so
exe         :=
soflag      := -shared
fpicflags   := -fPIC
thread_lib  := -pthread -lrt
sock_lib    := -lcares -lssl -lcrypto
dynlink_lib := -lpcre2-8 -lpcre2-32 -lz -ldl
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

lnk_lib  := -Wl,--push-state -Wl,-Bstatic
lnk_lib  += $(libd)/libraims.a
lnk_dep  := $(libd)/libraims.a

dlnk_lib := -L$(pwd)/$(libd) -lraims
dlnk_dep := $(libd)/libraims.$(dll)
ms_dlnk_dep :=

ifneq (,$(ds_home))
ds_lib      := $(ds_home)/$(libd)/libraids.a
ds_dll      := $(ds_home)/$(libd)/libraids.$(dll)
lnk_lib     += $(ds_lib)
lnk_dep     += $(ds_lib)
dlnk_lib    += -L$(ds_home)/$(libd) -lraids
ms_dlnk_dep += $(ds_dll)
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
ms_dlnk_dep += $(md_dll)
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
ms_dlnk_dep += $(dec_dll)
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
ms_dlnk_dep += $(lc_dll)
rpath4       = ,-rpath,$(pwd)/$(lc_home)/$(libd)
lc_includes  = -I$(lc_home)/include
else
lnk_lib     += -llinecook
dlnk_lib    += -llinecook
endif

ifneq (,$(h3_home))
h3_lib      := $(h3_home)/$(libd)/libh3lib.a
h3_dll      := $(h3_home)/$(libd)/libh3lib.$(dll)
lnk_lib     += $(h3_lib)
lnk_dep     += $(h3_lib)
dlnk_lib    += -L$(h3_home)/$(libd) -lh3lib
ms_dlnk_dep += $(h3_dll)
rpath5       = ,-rpath,$(pwd)/$(h3_home)/$(libd)
h3_includes  = -I$(h3_home)/src/h3lib/include
else
lnk_lib     += -lh3lib
dlnk_lib    += -lh3lib
endif

ifneq (,$(rdb_home))
rdb_lib     := $(rdb_home)/$(libd)/librdbparser.a
rdb_dll     := $(rdb_home)/$(libd)/librdbparser.$(dll)
lnk_lib     += $(rdb_lib)
lnk_dep     += $(rdb_lib)
dlnk_lib    += -L$(rdb_home)/$(libd) -lrdbparser
ms_dlnk_dep += $(rdb_dll)
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
ms_dlnk_dep += $(kv_dll)
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
ms_dlnk_dep += $(pgm_dll)
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
ms_dlnk_dep += $(sassrv_dll)
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
ms_dlnk_dep += $(natsmd_dll)
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
ms_dlnk_dep += $(lzf_dll)
rpath11      = ,-rpath,$(pwd)/$(lzf_home)/$(libd)
lzf_includes = -I$(lzf_home)/include
else
lnk_lib     += -llzf
dlnk_lib    += -llzf
includes    += -I/usr/include/liblzf
endif

dlnk_dep += $(ms_dlnk_dep)
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
transport_includes          := $(pgm_includes) $(natsmd_includes) $(sassrv_includes) $(ds_includes)
session_tport_includes      := $(pgm_includes) $(natsmd_includes) $(sassrv_includes) $(ds_includes)
conn_mgr_includes           := $(pgm_includes) $(natsmd_includes) $(sassrv_includes) $(ds_includes)
ev_pgm_transport_includes   := $(pgm_includes)
pgm_sock_includes           := $(pgm_includes)
console_includes            := $(natsmd_includes) $(sassrv_includes) $(ds_includes) $(lc_includes)
ev_telnet_includes          := $(ds_includes) $(lc_includes)
ev_web_includes             := $(ds_includes)
server_includes             := $(ds_includes) $(lc_includes)

session_defines := -DMS_VER=$(ver_build)
libraims_files := session user_db heartbeat auth peer link_state adjacency \
                  config user msg sub pat transport session_tport \
		  conn_mgr console stats adj_graph adj_io gen_config \
		  crypt poly1305 ec25519 ed25519 sha512 aes \
		  ev_tcp_aes ev_tcp_transport ev_pgm_transport pgm_sock \
		  ev_inbox_transport ev_telnet ev_web ev_rv_transport \
		  ev_name_svc
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
$(libd)/libraims.$(dll): $(libraims_dbjs) $(ms_dlnk_dep)

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
ms_gen_key_lnk   := $(dlnk_lib)

$(bind)/ms_gen_key$(exe): $(ms_gen_key_objs) $(ms_gen_key_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/ms_gen_key$(exe)
all_depends += $(ms_gen_key_deps)

kdftest_files := kdftest
kdftest_cfile := test/kdftest.cpp
kdftest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(kdftest_files)))
kdftest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(kdftest_files)))
kdftest_libs  :=
kdftest_lnk   := $(dlnk_lib)

$(bind)/kdftest$(exe): $(kdftest_objs) $(kdftest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/kdftest$(exe)
all_depends += $(kdftest_deps)

mactest_files := mactest
mactest_cfile := test/mactest.cpp
mactest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(mactest_files)))
mactest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(mactest_files)))
mactest_libs  :=
mactest_lnk   := $(dlnk_lib)

$(bind)/mactest$(exe): $(mactest_objs) $(mactest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/mactest$(exe)
all_depends += $(mactest_deps)

polytest_files := polytest
polytest_cfile := test/polytest.cpp
polytest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(polytest_files)))
polytest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(polytest_files)))
polytest_libs  :=
polytest_lnk   := $(dlnk_lib)

$(bind)/polytest$(exe): $(polytest_objs) $(polytest_libs) $(dlnk_dep) $(lnk_dep)

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
curvetest_lnk   := $(dlnk_lib)

$(bind)/curvetest$(exe): $(curvetest_objs) $(curvetest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/curvetest$(exe)
all_depends += $(curvetest_deps)

dsatest_files := dsatest
dsatest_cfile := test/dsatest.cpp
dsatest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(dsatest_files)))
dsatest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(dsatest_files)))
dsatest_libs  :=
dsatest_lnk   := $(dlnk_lib)

$(bind)/dsatest$(exe): $(dsatest_objs) $(dsatest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/dsatest$(exe)
all_depends += $(dsatest_deps)

sigtest_files := sigtest
sigtest_cfile := test/sigtest.cpp
sigtest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(sigtest_files)))
sigtest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(sigtest_files)))
sigtest_libs  :=
sigtest_lnk   := $(dlnk_lib)

$(bind)/sigtest$(exe): $(sigtest_objs) $(sigtest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/sigtest$(exe)
all_depends += $(sigtest_deps)

shatest_files := shatest
shatest_cfile := test/shatest.cpp
shatest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(shatest_files)))
shatest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(shatest_files)))
shatest_libs  :=
shatest_lnk   := $(dlnk_lib)

$(bind)/shatest$(exe): $(shatest_objs) $(shatest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/shatest$(exe)
all_depends += $(shatest_deps)

aestest_files := aestest
aestest_cfile := test/aestest.cpp
aestest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(aestest_files)))
aestest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(aestest_files)))
aestest_libs  :=
aestest_lnk   := $(dlnk_lib)

$(bind)/aestest$(exe): $(aestest_objs) $(aestest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/aestest$(exe)
all_depends += $(aestest_deps)

matchtest_files := matchtest
matchtest_cfile := test/matchtest.cpp
matchtest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(matchtest_files)))
matchtest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(matchtest_files)))
matchtest_libs  :=
matchtest_lnk   := $(dlnk_lib)

$(bind)/matchtest$(exe): $(matchtest_objs) $(matchtest_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/matchtest$(exe)
all_depends += $(matchtest_deps)

ms_test_adj_files := g
ms_test_adj_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ms_test_adj_files)))
ms_test_adj_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ms_test_adj_files)))
ms_test_adj_libs  :=
ms_test_adj_lnk   := $(dlnk_lib)

$(bind)/ms_test_adj$(exe): $(ms_test_adj_objs) $(ms_test_adj_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/ms_test_adj$(exe)
all_depends += $(ms_test_adj_deps)

parse_config_files := parse_config
parse_config_cfile := test/parse_config.cpp
parse_config_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(parse_config_files)))
parse_config_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(parse_config_files)))
parse_config_libs  :=
parse_config_lnk   := $(dlnk_lib)

$(bind)/parse_config$(exe): $(parse_config_objs) $(parse_config_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/parse_config$(exe)
all_depends += $(parse_config_deps)

test_tcp_aes_files := test_tcp_aes
test_tcp_aes_cfile := test/test_tcp_aes.cpp
test_tcp_aes_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(test_tcp_aes_files)))
test_tcp_aes_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(test_tcp_aes_files)))
test_tcp_aes_libs  :=
test_tcp_aes_lnk   := $(dlnk_lib)

$(bind)/test_tcp_aes$(exe): $(test_tcp_aes_objs) $(test_tcp_aes_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/test_tcp_aes$(exe)
all_depends += $(test_tcp_aes_deps)

test_conn_files := test_conn
test_conn_cfile := test/test_conn.cpp
test_conn_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(test_conn_files)))
test_conn_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(test_conn_files)))
test_conn_libs  :=
test_conn_lnk   := $(dlnk_lib)

$(bind)/test_conn$(exe): $(test_conn_objs) $(test_conn_libs) $(dlnk_dep) $(lnk_dep)

all_exes    += $(bind)/test_conn$(exe)
all_depends += $(test_conn_deps)

parse_pcap_files := parse_pcap
parse_pcap_cfile := test/parse_pcap.cpp
parse_pcap_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(parse_pcap_files)))
parse_pcap_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(parse_pcap_files)))
parse_pcap_libs  :=
parse_pcap_lnk   := $(dlnk_lib) -lpcap

$(bind)/parse_pcap$(exe): $(parse_pcap_objs) $(parse_pcap_libs) $(dlnk_dep) $(lnk_dep)

#all_exes    += $(bind)/parse_pcap$(exe)
#all_depends += $(parse_pcap_deps)

ms_server_files := server
ms_server_cfile := src/server.cpp
ms_server_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ms_server_files)))
ms_server_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ms_server_files)))
ms_server_libs  :=
ms_server_lnk   := $(dlnk_lib)

$(bind)/ms_server$(exe): $(ms_server_objs) $(ms_server_libs) $(dlnk_dep) $(lnk_dep)

#ms_server_libs  :=
#ms_server_lnk   := $(lnk_lib)

#$(bind)/ms_server$(exe): $(ms_server_objs) $(ms_server_libs) $(lnk_dep)

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
all: $(gen_files) $(all_libs) $(all_dlls) $(all_exes)

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

# --- code signing (Authenticode + NuGet) ------------------------------------
# Signs when a key is present: SIGN_PFX defaults to ~/.rai-codesign/rai-codesign.pfx
# (self-signed 10y cert, public half rai-codesign.cer next to it; the private key
# never goes in a repo or package).  Without a key dist_win says "unsigned" and
# carries on, so COPR/CI builds are unaffected.  jsign (github.com/ebourg/jsign)
# signs the PE files; the same step moves to Azure Trusted Signing later by
# changing only its arguments (--storetype TRUSTEDSIGNING ...).  The nupkg is
# signed with dotnet nuget sign and the same cert (customers pin its SHA-256
# fingerprint with <trustedSigners>).  RFC 3161 timestamps keep the signatures
# valid after the cert expires.
SIGN_PFX       ?= $(wildcard $(HOME)/.rai-codesign/rai-codesign.pfx)
SIGN_PASS_FILE ?= $(dir $(SIGN_PFX))pass.txt
SIGN_CER       ?= $(dir $(SIGN_PFX))rai-codesign.cer
SIGN_TSA       ?= http://timestamp.digicert.com
ifneq (,$(SIGN_PFX))
sign_pe    = jsign --keystore $(SIGN_PFX) --storepass file:$(SIGN_PASS_FILE) --alias rai-codesign \
               --alg SHA-256 --tsaurl $(SIGN_TSA) --tsmode RFC3161 $(1)
sign_nupkg = dotnet nuget sign $(1) --certificate-path $(SIGN_PFX) \
               --certificate-password "$$(cat $(SIGN_PASS_FILE))" --timestamper $(SIGN_TSA)
sign_note  = echo "\# signed: $$(openssl x509 -in $(SIGN_CER) -noout -subject -fingerprint -sha256 | tr '\n' ' ')"
else
sign_pe    = echo "unsigned (no SIGN_PFX): $(1)"
sign_nupkg = echo "unsigned (no SIGN_PFX): $(1)"
sign_note  = echo "\# unsigned"
endif

# --- windows distribution (make port_extra=-mingw dist_win) ------------------
# ms_server.exe + ms_gen_key.exe (statically linked against the sibling libs),
# the mingw runtime dlls (openssl, pcre2, c-ares, zlib, winpthread), raisvc.exe
# (runs ms_server as a Windows service, see win/raisvc.c) and an evaluation
# config (win/config: rv 7500, nats 4222, redis 6379, telnet 2222; the keys are
# generated at install time with ms_gen_key).  Produces
# <build_dir>/dist/raims-<ver>-win64.zip and, with makensis (mingw32-nsis),
# raims-<ver>-win64-setup.exe which installs and starts the service.
mingw_bin   := /usr/x86_64-w64-mingw32/sys-root/mingw/bin
mingw_rtdll := libcares-2.dll libcrypto-3-x64.dll libssl-3-x64.dll libpcre2-8-0.dll \
               libpcre2-32-0.dll libwinpthread-1.dll zlib1.dll
dist_name   := $(name)-$(ver_build)-win64
distd       := $(build_dir)/dist/$(dist_name)
dist_strip  := win/dist-strip.sh
dist_dbgd   := $(build_dir)/dist/$(dist_name)-debug

$(bind)/raisvc$(exe): win/raisvc.c
	$(CC) -O2 -Wall -Wextra -o $@ $< -ladvapi32

.PHONY: dist_win
dist_win: all $(bind)/raisvc$(exe)
	rm -rf $(distd) $(dist_dbgd) && mkdir -p $(distd)/bin $(distd)/config $(distd)/log $(dist_dbgd)
	for f in ms_server ms_gen_key ms_test_adj raisvc ; do $(dist_strip) $(bind)/$$f.exe $(distd)/bin/$$f.exe $(dist_dbgd) ; done
	for d in $(mingw_rtdll) ; do cp -f $(mingw_bin)/$$d $(distd)/bin/ ; done
	cp -f win/config/*.yaml $(distd)/config/
	cp -f win/README-windows.md $(distd)/README.md
	$(call sign_pe,$(distd)/bin/*.exe $(distd)/bin/*.dll)
	# which source built this: this repo and every sibling, plus the toolchain
	{ echo "# $(dist_name) built $$(date -u +%Y-%m-%dT%H:%MZ) on $$(hostname) with $$(x86_64-w64-mingw32-gcc --version | head -1)" ; \
	  echo "# repo  describe  commit  origin   (debug symbols: $(dist_name)-debug.zip, unpack into bin/)" ; \
	  $(sign_note) ; \
	  ./deps.sh -s ; } > $(distd)/SOURCES.txt
	cp -f $(distd)/SOURCES.txt $(dist_dbgd)/
	( cd $(build_dir)/dist && rm -f $(dist_name).zip $(dist_name)-debug.zip && zip -qr $(dist_name).zip $(dist_name) && zip -qr $(dist_name)-debug.zip $(dist_name)-debug )
	@if command -v makensis >/dev/null 2>&1 ; then \
	  makensis -V2 -DNAME=$(name) -DVERSION=$(version) -DVER_BUILD=$(ver_build) -DSRC=$(abspath $(distd)) \
	           -DOUT=$(abspath $(build_dir)/dist/$(dist_name)-setup.exe) win/raims.nsi && \
	  $(call sign_pe,$(build_dir)/dist/$(dist_name)-setup.exe) ; \
	else echo "makensis not found (dnf install mingw32-nsis), zip only" ; fi
	@ls -la $(build_dir)/dist/*.zip $(build_dir)/dist/*.exe 2>/dev/null

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

