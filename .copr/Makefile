outdir ?= rpmbuild/SRPMS
name   := raims
spec   := rpm/$(name).spec
date   := $(shell date +"%a %b %d %Y")
rpmdir := $(shell pwd)

git_hash    := $(shell git rev-parse --short=8 HEAD)
major_num   := 1
minor_num   := 47
patch_num   := 0
build_num   := 104
version     := $(major_num).$(minor_num).$(patch_num)
ver_build   := $(version)-$(build_num)
name_ver    := $(name)-$(ver_build)
rpm_src_dir := rpmbuild/SOURCES/$(name)-$(version)
srctree     := .git src include GNUmakefile .copr deb rpm web doc test
release     := $(shell if [ -x /bin/rpmspec ] ; then \
                   /bin/rpmspec -q rpm/$(name).spec | head -1 | sed 's/.*999.999-99999.//' | sed 's/.src//' ; fi)

.PHONY: srpm
srpm: $(outdir)/$(name_ver).$(release).src.rpm

$(outdir)/$(name_ver).$(release).src.rpm: rpmbuild/SOURCES/$(name_ver).tar.gz
	mkdir -p $(outdir)
	/bin/rpmbuild --root $(rpmdir) -D'_topdir rpmbuild' -D'_srcrpmdir $(outdir)' -D'_sourcedir rpmbuild/SOURCES' -bs rpmbuild/SPECS/$(name).spec

rpmbuild/SOURCES/$(name_ver).tar.gz:
	mkdir -p rpmbuild/RPMS rpmbuild/SRPMS rpmbuild/BUILD rpmbuild/SOURCES rpmbuild/SPECS
	sed -e "s/99999/$(build_num)/" \
	    -e "s/999.999/$(version)/" \
	    -e "s/_openpgm_st_dep/>= $(openpgm_st_dep)/" \
	    -e "s/_sassrv_dep/>= $(sassrv_dep)/" \
	    -e "s/_natsmd_dep/>= $(natsmd_dep)/" \
	    -e "s/_raids_dep/>= $(raids_dep)/" \
	    -e "s/_raikv_dep/>= $(raikv_dep)/" \
	    -e "s/_h3lib_dep/>= $(h3lib_dep)/" \
	    -e "s/_linecook_dep/>= $(linecook_dep)/" \
	    -e "s/_raimd_dep/>= $(raimd_dep)/" \
	    -e "s/_rdbparser_dep/>= $(rdbparser_dep)/" \
	    -e "s/_libdecnumber_dep/>= $(libdecnumber_dep)/" \
	    -e "s/Sat Jan 01 2000/$(date)/" < rpm/$(name).spec > rpmbuild/SPECS/$(name).spec
	mkdir -p $(rpm_src_dir)
	for i in $(srctree) ; do ln -sf ../../../$$i $(rpm_src_dir) ; done
	( cd rpmbuild/SOURCES && tar chzf $(name_ver).tar.gz --exclude=".*.sw*" $(name)-$(version) && rm -r -f $(name)-$(version) )

.PHONY: spec_version
spec_version:
	@echo "$(name)_dep := $(major_num).$(minor_num)"
