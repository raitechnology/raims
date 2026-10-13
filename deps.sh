#!/bin/bash
# deps.sh — clone (and optionally build) this repo's sibling dependencies.
#
# The dependency list comes from build_depends.mak (the same file the srpm
# target substitutes into rpm BuildRequires), so there is exactly one place
# that names the deps.  Repos are cloned as SIBLINGS of this checkout
# (../raikv, ../raimd, ...), which is the layout the GNUmakefile's
# -I../<dep>/include and ../<dep>/FC43_*/lib64 link paths expect.
#
#   ./deps.sh          clone missing siblings
#   ./deps.sh -b       clone missing siblings, then build all in dep order
#   ./deps.sh -n       dry run (show what would happen)
#   ./deps.sh -b port_extra=-mingw   extra args are passed to every make
#                                    (mingw-w64 cross build for Windows)
#   ./deps.sh -s       print the source revision of this repo and every
#                      sibling (dist_win puts it in SOURCES.txt)
#
# Versions in build_depends.mak are rpm BuildRequires minimums; master of
# each dep normally satisfies them.  To pin exactly, check out matching
# tags in the sibling checkouts after cloning.
#
# Prefer packages?  The whole chain publishes on COPR:
#   dnf copr enable injinj/rel && dnf install rvcache
set -e

ORG="${ORG:-https://github.com/raitechnology}"
# repos that live under a different org (master there kicks the COPR rel build)
org_for() { case "$1" in linecook|rdbparser) echo "https://github.com/injinj" ;; *) echo "$ORG" ;; esac; }
# repos whose buildable branch is not the github default (openpgm master is
# upstream-pristine; the GNUmakefile port lives on 'rai')
branch_for() { case "$1" in openpgm) echo rai ;; *) echo "" ;; esac; }
# build_depends.mak names rpm packages; map the ones whose repo is named differently
repo_for() { case "$1" in h3lib) echo h3 ;; hdrhist) echo HdrHistogram_c ;; openpgm_st) echo openpgm ;; *) echo "$1" ;; esac; }
HERE="$(cd "$(dirname "$0")" && pwd)"
PARENT="$(dirname "$HERE")"
DEPFILE="$HERE/build_depends.mak"

# global topological order (leaves first); filtered by what DEPFILE names
TOPO="libdecnumber raikv raimd h3 linecook rdbparser HdrHistogram_c openpgm
      sassrv natsmd raids omm raims raimdapi"

build=0; dry=0; sources=0
while getopts "bnsh" o; do case "$o" in
  b) build=1 ;;
  n) dry=1 ;;
  s) sources=1 ;;
  *) sed -n '2,20p' "$0"; exit 0 ;;
esac; done
shift $((OPTIND-1))   # remaining args go to make (e.g. port_extra=-mingw)

[ -f "$DEPFILE" ] || { echo "missing $DEPFILE" >&2; exit 1; }

# "raikv_dep := 1.42" -> "raikv"
deps="$(sed -n 's/^\([A-Za-z0-9_]*\)_dep[[:space:]]*:=.*/\1/p' "$DEPFILE" | while read -r d; do repo_for "$d"; done)"
[ -n "$deps" ] || { echo "no *_dep entries in $DEPFILE" >&2; exit 1; }

want() { echo "$deps" | grep -qx "$1"; }

ordered=""
for r in $TOPO; do want "$r" && ordered="$ordered $r"; done
# anything in DEPFILE not in TOPO goes last (new dep: extend TOPO)
for r in $deps; do
  case " $ordered " in *" $r "*) ;; *) ordered="$ordered $r"
    echo "warn: $r not in TOPO order list, building last" >&2 ;;
  esac
done

if [ "$sources" = 1 ]; then
  # repo  describe  commit  origin   (describe is a tag if one is reachable,
  # else the short hash; -dirty marks uncommitted changes)
  for d in "$HERE" $(for r in $ordered; do echo "$PARENT/$r"; done); do
    [ -d "$d/.git" ] || { printf '%-14s %s\n' "$(basename "$d")" "MISSING"; continue; }
    printf '%-14s %-28s %s  %s\n' "$(basename "$d")" \
      "$(git -C "$d" describe --always --dirty --tags 2>/dev/null)" \
      "$(git -C "$d" rev-parse HEAD)" \
      "$(git -C "$d" remote get-url origin 2>/dev/null)"
  done
  exit 0
fi

echo "deps (build order):$ordered"

for r in $ordered; do
  if [ ! -d "$PARENT/$r/.git" ]; then
    br="$(branch_for "$r")"
    echo "clone: $(org_for "$r")/$r${br:+ @$br} -> $PARENT/$r"
    [ "$dry" = 1 ] || git clone ${br:+-b "$br"} "$(org_for "$r")/$r" "$PARENT/$r"
  else
    echo "have:  $PARENT/$r"
  fi
done

if [ "$build" = 1 ]; then
  for r in $ordered; do
    echo "make:  $PARENT/$r"
    [ "$dry" = 1 ] || make -C "$PARENT/$r" -j"$(nproc)" "$@"
  done
  echo "make:  $HERE"
  [ "$dry" = 1 ] || make -C "$HERE" -j"$(nproc)" "$@"
fi
