# defines a directory for build, for example, RH6_x86_64
lsb_dist     := $(shell if [ -x /usr/bin/lsb_release ] ; then lsb_release -is ; else echo Linux ; fi)
lsb_dist_ver := $(shell if [ -x /usr/bin/lsb_release ] ; then lsb_release -rs | sed 's/[.].*//' ; else uname -r | sed 's/[-].*//' ; fi)
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

# use 'make port_extra=-g' for debug build
ifeq (-g,$(findstring -g,$(port_extra)))
  DEBUG = true
endif

CC          ?= gcc
CXX         ?= g++
cc          := $(CC)
cpp         := $(CXX)
# if not linking libstdc++
ifdef NO_STL
cppflags    := -std=c++11 -fno-rtti -fno-exceptions
cpplink     := $(CC)
else
cppflags    := -std=c++11
cpplink     := $(CXX)
endif
arch_cflags := -mavx -maes -fno-omit-frame-pointer
gcc_wflags  := -Wall -Wextra -Werror
fpicflags   := -fPIC
soflag      := -shared

ifdef DEBUG
default_cflags := -ggdb
else
default_cflags := -ggdb -O3 -Ofast
endif
# rpmbuild uses RPM_OPT_FLAGS
CFLAGS := $(default_cflags)
#RPM_OPT_FLAGS ?= $(default_cflags)
#CFLAGS ?= $(RPM_OPT_FLAGS)
cflags := $(gcc_wflags) $(CFLAGS) $(arch_cflags)

# where to find the raids/xyz.h files
INCLUDES    ?= -Iinclude -Iraikv/include -Iraimd/include -Iraids/include -Ilinecook/include
includes    := $(INCLUDES)
DEFINES     ?=
defines     := $(DEFINES)
cpp_lnk     :=
sock_lib    :=
math_lib    := -lm
thread_lib  := -pthread -lrt

# test submodules exist (they don't exist for dist_rpm, dist_dpkg targets)
have_md_submodule     := $(shell if [ -f ./raimd/GNUmakefile ]; then echo yes; else echo no; fi )
have_dec_submodule    := $(shell if [ -f ./raimd/libdecnumber/GNUmakefile ]; then echo yes; else echo no; fi )
have_kv_submodule     := $(shell if [ -f ./raikv/GNUmakefile ]; then echo yes; else echo no; fi )
have_ds_submodule     := $(shell if [ -f ./raids/GNUmakefile ]; then echo yes; else echo no; fi )
have_lc_submodule     := $(shell if [ -f ./linecook/GNUmakefile ]; then echo yes; else echo no; fi )
have_h3_submodule     := $(shell if [ -f ./raids/h3/GNUmakefile ]; then echo yes; else echo no; fi )
have_rdb_submodule    := $(shell if [ -f ./raids/rdbparser/GNUmakefile ]; then echo yes; else echo no; fi )
have_pgm_submodule    := $(shell if [ -f ./openpgm/GNUmakefile ]; then echo yes; else echo no; fi )
have_sassrv_submodule := $(shell if [ -f ./sassrv/GNUmakefile ]; then echo yes; else echo no; fi )

lnk_lib     := $(libd)/libraims.a
dlnk_lib    :=
lnk_dep     := $(libd)/libraims.a
dlnk_dep    :=

ifeq (yes,$(have_ds_submodule))
ds_lib      := raids/$(libd)/libraids.a
ds_dll      := raids/$(libd)/libraids.so
lnk_lib     += $(ds_lib)
lnk_dep     += $(ds_lib)
dlnk_lib    += -Lraids/$(libd) -lraids
dlnk_dep    += $(ds_dll)
rpath1       = ,-rpath,$(pwd)/raids/$(libd)
else
lnk_lib     += -lraids
dlnk_lib    += -lraids
endif

ifeq (yes,$(have_md_submodule))
md_lib      := raimd/$(libd)/libraimd.a
md_dll      := raimd/$(libd)/libraimd.so
lnk_lib     += $(md_lib)
lnk_dep     += $(md_lib)
dlnk_lib    += -Lraimd/$(libd) -lraimd
dlnk_dep    += $(md_dll)
rpath2       = ,-rpath,$(pwd)/raimd/$(libd)
else
lnk_lib     += -lraimd
dlnk_lib    += -lraimd
endif

ifeq (yes,$(have_dec_submodule))
dec_lib     := raimd/libdecnumber/$(libd)/libdecnumber.a
dec_dll     := raimd/libdecnumber/$(libd)/libdecnumber.so
lnk_lib     += $(dec_lib)
lnk_dep     += $(dec_lib)
dlnk_lib    += -Lraimd/libdecnumber/$(libd) -ldecnumber
dlnk_dep    += $(dec_dll)
rpath3       = ,-rpath,$(pwd)/raimd/libdecnumber/$(libd)
else
lnk_lib     += -ldecnumber
dlnk_lib    += -ldecnumber
endif

ifeq (yes,$(have_lc_submodule))
lc_lib      := linecook/$(libd)/liblinecook.a
lc_dll      := linecook/$(libd)/liblinecook.so
lnk_lib     += $(lc_lib)
lnk_dep     += $(lc_lib)
dlnk_lib    += -Llinecook/$(libd) -llinecook
dlnk_dep    += $(lc_dll)
rpath4       = ,-rpath,$(pwd)/linecook/$(libd)
else
lnk_lib     += -llinecook
dlnk_lib    += -llinecook
endif

ifeq (yes,$(have_h3_submodule))
h3_lib      := raids/h3/$(libd)/libh3.a
h3_dll      := raids/h3/$(libd)/libh3.so
lnk_lib     += $(h3_lib)
lnk_dep     += $(h3_lib)
dlnk_lib    += -Lraids/h3/$(libd) -lh3
dlnk_dep    += $(h3_dll)
rpath5       = ,-rpath,$(pwd)/raids/h3/$(libd)
else
lnk_lib     += -lh3
dlnk_lib    += -lh3
endif

ifeq (yes,$(have_rdb_submodule))
rdb_lib     := raids/rdbparser/$(libd)/librdbparser.a
rdb_dll     := raids/rdbparser/$(libd)/librdbparser.so
lnk_lib     += $(rdb_lib)
lnk_dep     += $(rdb_lib)
dlnk_lib    += -Lraids/rdbparser/$(libd) -lrdbparser
dlnk_dep    += $(rdb_dll)
rpath6       = ,-rpath,$(pwd)/raids/rdbparser/$(libd)
else
lnk_lib     += -lrdbparser
dlnk_lib    += -lrdbparser
endif

ifeq (yes,$(have_kv_submodule))
kv_lib      := raikv/$(libd)/libraikv.a
kv_dll      := raikv/$(libd)/libraikv.so
lnk_lib     += $(kv_lib)
lnk_dep     += $(kv_lib)
dlnk_lib    += -Lraikv/$(libd) -lraikv
dlnk_dep    += $(kv_dll)
rpath7       = ,-rpath,$(pwd)/raikv/$(libd)
else
lnk_lib     += -lraikv
dlnk_lib    += -lraikv
endif

ifeq (yes,$(have_pgm_submodule))
pgm_lib     := openpgm/$(libd)/libopenpgm_st.a
pgm_dll     := openpgm/$(libd)/libopenpgm_st.so
lnk_lib     += $(pgm_lib)
lnk_dep     += $(pgm_lib)
dlnk_lib    += -Lopenpgm/$(libd) -lopenpgm_st
dlnk_dep    += $(pgm_dll)
rpath8       = ,-rpath,$(pwd)/openpgm/$(libd)
includes    += -Iopenpgm/openpgm/pgm/include
else
lnk_lib     += -lopenpgm_st
dlnk_lib    += -lopenpgm_st
endif

ifeq (yes,$(have_sassrv_submodule))
sassrv_lib  := sassrv/$(libd)/libsassrv.a
sassrv_dll  := sassrv/$(libd)/libsassrv.so
lnk_lib     += $(sassrv_lib)
lnk_dep     += $(sassrv_lib)
dlnk_lib    += -Lsassrv/$(libd) -lsassrv
dlnk_dep    += $(pgm_dll)
rpath9       = ,-rpath,$(pwd)/sassrv/$(libd)
includes    += -Isassrv/include
else
lnk_lib     += -lsassrv
dlnk_lib    += -lsassrv
endif

lnk_lib     += -lpcre2-32 -lpcre2-8 -lcrypto -llzf
dlnk_lib    += -lpcre2-32 -lpcre2-8 -lcrypto -llzf
rpath       := -Wl,-rpath,$(pwd)/$(libd)$(rpath1)$(rpath2)$(rpath3)$(rpath4)$(rpath5)$(rpath6)$(rpath7)$(rpath8)$(rpath9)

.PHONY: everything
everything: $(kv_lib) $(dec_lib) $(md_lib) $(lc_lib) $(h3_lib) $(rdb_lib) $(ds_lib) $(pgm_lib) $(sassrv_lib) all

clean_subs :=
dlnk_dll_depend :=
dlnk_lib_depend :=

# build submodules if have them
ifeq (yes,$(have_kv_submodule))
$(kv_lib) $(kv_dll):
	$(MAKE) -C raikv
.PHONY: clean_kv
clean_kv:
	$(MAKE) -C raikv clean
clean_subs += clean_kv
endif
ifeq (yes,$(have_dec_submodule))
$(dec_lib) $(dec_dll):
	$(MAKE) -C raimd/libdecnumber
.PHONY: clean_dec
clean_dec:
	$(MAKE) -C raimd/libdecnumber clean
clean_subs += clean_dec
endif
ifeq (yes,$(have_md_submodule))
$(md_lib) $(md_dll):
	$(MAKE) -C raimd
.PHONY: clean_md
clean_md:
	$(MAKE) -C raimd clean
clean_subs += clean_md
endif
ifeq (yes,$(have_ds_submodule))
$(ds_lib) $(ds_dll):
	$(MAKE) -C raids
.PHONY: clean_ds
clean_ds:
	$(MAKE) -C raids clean
clean_subs += clean_ds
endif
ifeq (yes,$(have_lc_submodule))
$(lc_lib) $(lc_dll):
	$(MAKE) -C linecook
.PHONY: clean_lc
clean_lc:
	$(MAKE) -C linecook clean
clean_subs += clean_lc
endif
ifeq (yes,$(have_h3_submodule))
$(h3_lib) $(h3_dll):
	$(MAKE) -C raids/h3
.PHONY: clean_h3
clean_h3:
	$(MAKE) -C raids/h3 clean
clean_subs += clean_h3
endif
ifeq (yes,$(have_rdb_submodule))
$(rdb_lib) $(rdb_dll):
	$(MAKE) -C raids/rdbparser
.PHONY: clean_rdb
clean_rdb:
	$(MAKE) -C raids/rdbparser clean
clean_subs += clean_rdb
endif
ifeq (yes,$(have_pgm_submodule))
$(pgm_lib) $(pgm_dll):
	$(MAKE) -C openpgm
.PHONY: clean_pgm
clean_pgm:
	$(MAKE) -C openpgm clean
clean_subs += clean_pgm
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

libraims_files := config user transport ev_tcp_transport ev_pgm_transport \
                 pgm_sock ev_inbox_transport ev_telnet ev_rv_transport \
		 msg session heartbeat user_db auth peer link_state sub \
		 pat crypt poly1305 ec25519 ed25519 gen_config console
libraims_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(libraims_files)))
libraims_dbjs  := $(addprefix $(objd)/, $(addsuffix .fpic.o, $(libraims_files)))
libraims_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(libraims_files))) \
                   $(addprefix $(dependd)/, $(addsuffix .fpic.d, $(libraims_files)))
libraims_dlnk  := $(dlnk_lib)
libraims_spec  := $(version)-$(build_num)_$(git_hash)
libraims_ver   := $(major_num).$(minor_num)

$(libd)/libraims.a: $(libraims_objs)
$(libd)/libraims.so: $(libraims_dbjs) $(dlnk_dep)

all_libs    += $(libd)/libraims.a $(libd)/libraims.so
all_depends += $(libraims_deps)

#gen_user_files := gen_user
#gen_user_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(gen_user_files)))
#gen_user_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(gen_user_files)))
#gen_user_libs  :=
#gen_user_lnk   := $(lnk_lib)
#
#$(bind)/gen_user: $(gen_user_objs) $(gen_user_libs) $(lnk_dep)
#
#all_exes    += $(bind)/gen_user
#all_depends += $(gen_user_deps)

gen_cfg_files := gen_cfg
gen_cfg_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(gen_cfg_files)))
gen_cfg_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(gen_cfg_files)))
gen_cfg_libs  :=
gen_cfg_lnk   := $(lnk_lib)

$(bind)/gen_cfg: $(gen_cfg_objs) $(gen_cfg_libs) $(lnk_dep)

all_exes    += $(bind)/gen_cfg
all_depends += $(gen_cfg_deps)

kdftest_files := kdftest
kdftest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(kdftest_files)))
kdftest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(kdftest_files)))
kdftest_libs  :=
kdftest_lnk   := $(lnk_lib)

$(bind)/kdftest: $(kdftest_objs) $(kdftest_libs) $(lnk_dep)

all_exes    += $(bind)/kdftest
all_depends += $(kdftest_deps)

mactest_files := mactest
mactest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(mactest_files)))
mactest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(mactest_files)))
mactest_libs  :=
mactest_lnk   := $(lnk_lib)

$(bind)/mactest: $(mactest_objs) $(mactest_libs) $(lnk_dep)

all_exes    += $(bind)/mactest
all_depends += $(mactest_deps)

polytest_files := polytest
polytest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(polytest_files)))
polytest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(polytest_files)))
polytest_libs  :=
polytest_lnk   := $(lnk_lib)

$(bind)/polytest: $(polytest_objs) $(polytest_libs) $(lnk_dep)

all_exes    += $(bind)/polytest
all_depends += $(polytest_deps)

#ecdhtest_files := ecdhtest
#ecdhtest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ecdhtest_files)))
#ecdhtest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ecdhtest_files)))
#ecdhtest_libs  :=
#ecdhtest_lnk   := $(lnk_lib)

#$(bind)/ecdhtest: $(ecdhtest_objs) $(ecdhtest_libs) $(lnk_dep)

#all_exes    += $(bind)/ecdhtest
#all_depends += $(ecdhtest_deps)

curvetest_files := curvetest
curvetest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(curvetest_files)))
curvetest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(curvetest_files)))
curvetest_libs  :=
curvetest_lnk   := $(lnk_lib)

$(bind)/curvetest: $(curvetest_objs) $(curvetest_libs) $(lnk_dep)

all_exes    += $(bind)/curvetest
all_depends += $(curvetest_deps)

dsatest_files := dsatest
dsatest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(dsatest_files)))
dsatest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(dsatest_files)))
dsatest_libs  :=
dsatest_lnk   := $(lnk_lib)

$(bind)/dsatest: $(dsatest_objs) $(dsatest_libs) $(lnk_dep)

all_exes    += $(bind)/dsatest
all_depends += $(dsatest_deps)

#rsatest_files := rsatest
#rsatest_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(rsatest_files)))
#rsatest_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(rsatest_files)))
#rsatest_libs  :=
#rsatest_lnk   := $(lnk_lib)

#$(bind)/rsatest: $(rsatest_objs) $(rsatest_libs) $(lnk_dep)

#all_exes    += $(bind)/rsatest
#all_depends += $(rsatest_deps)

parse_config_files := parse_config
parse_config_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(parse_config_files)))
parse_config_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(parse_config_files)))
parse_config_libs  :=
parse_config_lnk   := $(lnk_lib)

$(bind)/parse_config: $(parse_config_objs) $(parse_config_libs) $(lnk_dep)

all_exes    += $(bind)/parse_config
all_depends += $(parse_config_deps)

test_client_files := client
test_client_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(test_client_files)))
test_client_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(test_client_files)))
test_client_libs  :=
test_client_lnk   := $(lnk_lib)

$(bind)/test_client: $(test_client_objs) $(test_client_libs) $(lnk_dep)

all_exes    += $(bind)/test_client
all_depends += $(test_client_deps)

all_dirs := $(bind) $(libd) $(objd) $(dependd)

# the default targets
.PHONY: all
all: $(all_libs) $(all_dlls) $(all_exes)

.PHONY: dnf_depend
dnf_depend:
	sudo dnf -y install make gcc-c++ git redhat-lsb openssl-devel pcre2-devel chrpath

.PHONY: yum_depend
yum_depend:
	sudo yum -y install make gcc-c++ git redhat-lsb openssl-devel pcre2-devel chrpath

.PHONY: deb_depend
deb_depend:
	sudo apt-get install -y install make g++ gcc devscripts libpcre2-dev chrpath git lsb-release libssl-dev

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

.PHONY: dist_bins
dist_bins: $(all_libs)

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

$(libd)/%.so:
	$(cpplink) $(soflag) $(rpath) $(cflags) -o $@.$($(*)_spec) -Wl,-soname=$(@F).$($(*)_ver) $($(*)_dbjs) $($(*)_dlnk) $(cpp_dll_lnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib) && \
	cd $(libd) && ln -f -s $(@F).$($(*)_spec) $(@F).$($(*)_ver) && ln -f -s $(@F).$($(*)_ver) $(@F)

$(bind)/%:
	$(cpplink) $(cflags) $(rpath) -o $@ $($(*)_objs) -L$(libd) $($(*)_lnk) $(cpp_lnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib)

$(bind)/%.static:
	$(cpplink) $(cflags) -o $@ $($(*)_objs) $($(*)_static_lnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib)

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

