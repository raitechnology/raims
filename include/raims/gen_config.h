#ifndef __rai__raims__gen_config_h__
#define __rai__raims__gen_config_h__

#include <raikv/bit_set.h>
#include <raims/user.h>

namespace rai {
namespace ms {

enum GenFileOp {      /*             phase 1           phase 2 */
  GEN_CREATE_FILE,    /* file.new -> file                      */
  GEN_REMOVE_FILE,    /* file     -> file.old       -> unlink  */
  GEN_OVERWRITE_FILE, /* file.new -> file, file.old -> unlink file.old */
  GEN_MK_DIR,         /* mkdir */
  GEN_RM_DIR          /* not used */
};

static const size_t GEN_PATH_MAX = 1024,
                    GEN_TEMP_MAX = 1028;
struct GenFileList;
struct GenFileTrans {
  GenFileTrans * next,
               * back;
  GenFileOp      op;
  int            phase;     /* if partially complete, phase 1 */
  const char   * descr;     /* description of file */
  size_t         len;       /* length of path */
  char           path[ 4 ]; /* the file or dir path */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  GenFileTrans( GenFileOp o,  const char *p,  size_t n ) noexcept;
  const char *op_str( void ) const noexcept;
  int check_if_changed( void ) noexcept;     /* compare new with old */
  int remove_if_equal( void ) noexcept;      /* compare and remove when equal */
  char *orig_path( char *p ) noexcept;       /* the target path */
  char *tmp_path( char *p ) noexcept;        /* a temp rename */
  int commit_phase1( void ) noexcept;        /* try to do phase 1 */
  int commit_phase2( void ) noexcept;        /* try to do phase 2 */
  void abort( void ) noexcept;               /* undo phases */
  static GenFileTrans * create_file_path( GenFileOp op,  const char *path,
                                          size_t n = 0 ) noexcept;
  static GenFileTrans * create_file_fmt( GenFileOp op,
                                         const char *fmt, ... ) noexcept
      __attribute__((format(printf,2,3)));
  static bool cat_trans( GenFileTrans *t,  const void *text,  size_t len,
                         const char *descr,  GenFileList &list ) noexcept;
  static bool trans_if_neq( GenFileTrans *t,  const char *descr,
                            GenFileList &list ) noexcept;

};

struct GenFileList : public kv::DLinkList< GenFileTrans > {
  size_t print_files( void ) noexcept;
  bool commit_phase1( void ) noexcept;
  bool commit_phase2( void ) noexcept;
  void abort( void ) noexcept;
};

struct GenUserSet : public kv::BitSpace { /* filter user hash */
  static const uint32_t USER_SET_SIZE = 16 * 1024;
  bool is_member( const char *user,  size_t user_len ) noexcept;
  void add_member( const char *user,  size_t user_len ) noexcept;
};

struct GenCfg {
  ServiceBuf  svc;      /* service being operated */
  GenFileList list;     /* list of file changes */
  GenUserSet  user_set; /* set of users affected */
  char      * salt_path;

  GenCfg() : salt_path( 0 ) {}
  int  check_dir( const char *dir_name,  bool create,
                  const char *descr ) noexcept;
  bool init_pass( const char *dir_name,  CryptPass &pass,
                  const char *pass_file, bool create_it ) noexcept;
  bool init_pass_salt( const char *dir_name,  CryptPass &pass,
                       const char *pass_file,  const char *salt_file,
                       bool create_it ) noexcept;
  bool copy_salt( const char *dir_name ) noexcept;
  bool copy_param( const char *orig_dir,  const char *dir_name ) noexcept;
  void add_user( const char *user,  size_t user_len,
                 const char *expire,  size_t expire_len,
                 CryptPass &pass ) noexcept;
  bool populate_directory( const char *dir_name,
                           bool want_transports,
                           bool want_param ) noexcept;
  bool populate_example_transports( const char *dir_name ) noexcept;
  bool populate_service2( const char *dir_name,  ServiceBuf &svc2,
                          bool include_pri ) noexcept;
  bool populate_service( const char *dir_name,  bool include_pri ) noexcept;
  bool populate_user( const char *dir_name,  UserElem *&u,
                      bool include_pri ) noexcept;
  bool populate_user_set( const char *dir_name ) noexcept;
  bool export_users( const char *dir_name,
                     ServiceBuf &svc2,  UserElem *for_u ) noexcept;
  bool export_user_svc( const char *orig_dir,  CryptPass &pass,
                        const char *user,  size_t user_len,
                        bool want_transports ) noexcept;
  bool revoke_user( const char *user, size_t user_len ) noexcept;
  bool remove_user( const char *di,  const char *user,
                    size_t user_len ) noexcept;
  void ask_commit( bool auto_yes ) noexcept;
  void abort( void ) {
    this->list.abort();
  }
};

}
}
#endif
