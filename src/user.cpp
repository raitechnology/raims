#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/crypt.h>
#include <raims/ecdh.h>
#include <raims/user.h>
#include <raimd/md_types.h>

using namespace rai;
using namespace kv;
using namespace ms;
using namespace md;

bool
rai::ms::init_pass( ConfigTree *tree,  CryptPass &pass,
                    const char *dir_name ) noexcept
{
  const char * pass_file = NULL,
             * salt_file = NULL;
  char         path[ 1024 ];
  if ( tree == NULL )
    return false;
  tree->find_parameter( "salt", salt_file, ".salt" );
  if ( ! make_path( path, sizeof( path ), "%s/%s", dir_name, salt_file ) ||
       ! pass.init_salt_file( path ) )
    return false;
  tree->find_parameter( "pass", pass_file, ".pass" );
  if ( ! make_path( path, sizeof( path ), "%s/%s", dir_name, pass_file ) ||
       ! pass.init_pass_file( path ) )
    return false;
  return true;
}

void
UserBuf::copy( const ConfigTree::User &u ) noexcept
{
  copy_max( this->user, this->user_len, MAX_USER_LEN, u.user.val, u.user.len );
  copy_max( this->service, this->service_len, MAX_SERVICE_LEN, u.svc.val,
            u.svc.len );
  copy_max( this->create, this->create_len, MAX_TIME_LEN, u.create.val,
            u.create.len );
  copy_max( this->expires, this->expires_len, MAX_TIME_LEN, u.expires.val,
            u.expires.len );
  copy_max( this->revoke, this->revoke_len, MAX_TIME_LEN, u.revoke.val,
            u.revoke.len );
  copy_max( this->pri, this->pri_len, MAX_ECDH_CIPHER_PRI_B64_LEN,
            u.pri.val, u.pri.len );
  copy_max( this->pub, this->pub_len, MAX_ECDH_CIPHER_PUB_B64_LEN,
            u.pub.val, u.pub.len );
  if ( this->pri_len == 0 )
    this->pri[ 0 ] = '\0';
  if ( this->pub_len == 0 )
    this->pub[ 0 ] = '\0';
  if ( this->pri_len != u.pri.len )
    fprintf( stderr, "pri len %u > %lu\n", u.pri.len,
             MAX_ECDH_CIPHER_PRI_B64_LEN );
  if ( this->pub_len != u.pub.len )
    fprintf( stderr, "pub len %u > %lu\n", u.pub.len,
             MAX_ECDH_CIPHER_PUB_B64_LEN );
}

static size_t
timestamp_now( char *time,  size_t maxlen )
{
  MDStamp stamp;
  stamp.stamp      = current_realtime_ns();
  stamp.resolution = MD_RES_NANOSECS;
  /* fill in resolution */
  for ( uint64_t i = 1000000; i > 10; i /= 10 ) {
    if ( ( stamp.stamp % i ) == 0 ) {
      uint64_t r;
      rand::fill_urandom_bytes( &r, sizeof( r ) );
      stamp.stamp += r % i;
    }
  }
  return stamp.get_string( time, maxlen );
}
/* offset for AES ctr mode enc/dec */
static inline uint64_t aes_ctr_off( size_t len ) { return ( len + 15 ) / 16; }

bool
UserBuf::gen_key( const char *user,  size_t ulen,  const char *svc,
                  size_t slen,  const char *expire,  size_t elen,
                  const CryptPass &pwd ) noexcept
{
  copy_max( this->user, this->user_len, MAX_USER_LEN, user, ulen );
  copy_max( this->service, this->service_len, MAX_SERVICE_LEN, svc, slen );
  copy_max( this->expires, this->expires_len, MAX_TIME_LEN, expire, elen );
  this->create_len = timestamp_now( this->create, sizeof( this->create ) );

  OpenSsl_ECDH ec;
  if ( ! ec.gen_key() )
    return false;
  return this->put_ecdh( pwd, ec, DO_BOTH );
}

uint64_t
UserBuf::get_expires( void ) const noexcept
{
  MDStamp stamp, stamp2;

  if ( this->expires_len == 0 )
    return 0;
  stamp.parse( this->create, this->create_len );
  stamp2.parse( this->expires, this->expires_len );
  
  uint64_t ns  = stamp.nanos(),
           ns2 = stamp2.nanos();
  if ( ns2 > ns )
    return ns2;
  return ns + ns2;
}

uint64_t
UserBuf::get_revoke( void ) const noexcept
{
  MDStamp stamp, stamp2;

  if ( this->revoke_len == 0 )
    return 0;
  stamp.parse( this->create, this->create_len );
  stamp2.parse( this->revoke, this->revoke_len );
  
  uint64_t ns  = stamp.nanos(),
           ns2 = stamp2.nanos();
  if ( ns2 > ns )
    return ns2;
  return ns + ns2;
}

bool
UserBuf::put_ecdh( const CryptPass &pwd,  OpenSsl_ECDH &ec,
                   WhichPubPri put_op ) noexcept
{
  uint64_t ctr = 0;
  HmacEncrypt< MAX_ECDH_CIPHER_PRI_LEN, MAX_ECDH_DER_PRI_LEN > der( ctr );

  der.init_kdf( *this, pwd );
  if ( (put_op & DO_PUB) != 0 ) {
    if ( ! ec.i2d_public( der.plain, der.plain_len ) )
      return false;
    this->pub_len = sizeof( this->pub );
    if ( ! der.encrypt( this->pub, this->pub_len ) )
      return false;
  }
  if ( (put_op & DO_PRI) != 0 ) {
    if ( ! ec.i2d_private( der.plain, der.plain_len ) ) /* encode to der */
      return false;
    ctr = aes_ctr_off( MAX_ECDH_DER_PUB_LEN );
    this->pri_len = sizeof( this->pri );
    if ( ! der.encrypt( this->pri, this->pri_len ) )
      return false;
  }
  return true;
}

bool
UserBuf::get_ecdh( const CryptPass &pwd,  OpenSsl_ECDH &ec,  WhichPubPri get_op,
                   void *pub_der_out, size_t *pub_sz_out ) const noexcept
{
  uint64_t ctr = 0;
  HmacDecrypt< MAX_ECDH_CIPHER_PRI_LEN, MAX_ECDH_DER_PRI_LEN > der( ctr );

  der.init_kdf( *this, pwd );
  if ( (get_op & DO_PUB) != 0 ) {
    if ( this->pub_len == 0 )
      return false;
    if ( ! der.decrypt( *this, this->pub, this->pub_len ) )
      return false;
    if ( ! ec.d2i_public( der.plain, der.plain_len ) )
      return false;
    if ( pub_der_out != NULL ) {
      ::memcpy( pub_der_out, der.plain, der.plain_len );
      *pub_sz_out = der.plain_len;
    }
  }
  if ( (get_op & DO_PRI) != 0 ) {
    if ( this->pri_len == 0 )
      return false;
    ctr += aes_ctr_off( MAX_ECDH_DER_PUB_LEN );
    if ( ! der.decrypt( *this, this->pri, this->pri_len ) )
      return false;
    if ( ! ec.d2i_private( der.plain, der.plain_len ) )
      return false;
  }
  return true;
}

int
UserBuf::cmp_user( const UserBuf &x,  const UserBuf &y ) noexcept
{
  return cmp_bytes( x.user, x.user_len, y.user, y.user_len );
}

int
UserBuf::cmp_user_create( const UserBuf &x,  const UserBuf &y ) noexcept
{
  int n = UserBuf::cmp_user( x, y );
  if ( n == 0 )
    n = cmp_bytes( x.create, x.create_len, y.create, y.create_len );
  return n;
}

static int
cmp_user_elem( const UserElem &x,  const UserElem &y ) noexcept
{
  return UserBuf::cmp_user_create( x.user, y.user );
}

static int
cmp_revoke_elem( const RevokeElem &x,  const RevokeElem &y ) noexcept
{
  return UserBuf::cmp_user_create( x.user->user, y.user->user );
}

bool
UserHmacData::decrypt( const CryptPass &pwd,  WhichPubPri get_op ) noexcept
{
  uint8_t pub_der[ MAX_ECDH_DER_PUB_LEN ];
  size_t  pub_len;

  if ( ! this->user.get_ecdh( pwd, this->ec, get_op, pub_der, &pub_len ) ) {
    fprintf( stderr, "Unable to get key for user \"%.*s\"\n",
             (int) this->user.user_len, this->user.user );
    return false;
  }
  this->kdf_hash.kdf_bytes( pub_der, pub_len );
  this->user_hmac.calc_4( this->kdf_hash, 
                          this->user.user,    this->user.user_len,
                          this->user.service, this->user.service_len,
                          this->user.create,  this->user.create_len,
                          this->user.expires, this->user.expires_len );
  if ( this->user.revoke_len > 0 )
    this->revoke_hmac.calc_5( this->kdf_hash, 
                              this->user.user,    this->user.user_len,
                              this->user.service, this->user.service_len,
                              this->user.create,  this->user.create_len,
                              this->user.expires, this->user.expires_len,
                              this->user.revoke,  this->user.revoke_len );
  else
    this->revoke_hmac.zero();
  return true;
}

bool
UserHmacData::calc_secret_hmac( UserHmacData &data2,
                                PolyHmacDigest &secret_hmac ) noexcept
{
  HashDigest ha;
  uint8_t    secret[ MAX_ECDH_SECRET_LEN ];
  size_t     secret_len = sizeof( secret );

  if ( ! this->ec.shared_secret( this->ec.pri, data2.ec.pub,
                                 secret, secret_len ) ) {
    fprintf( stderr, "Unable to get secret for user %.*s and %.*s\n",
             (int) this->user.user_len, this->user.user,
             (int) data2.user.user_len, data2.user.user );
    return false;
  }
  ha.kdf_bytes( secret, secret_len );

  if ( this->user_hmac < data2.user_hmac )
    secret_hmac.calc_2( ha, this->user_hmac.dig, HMAC_SIZE,
                            data2.user_hmac.dig, HMAC_SIZE );
  else
    secret_hmac.calc_2( ha, data2.user_hmac.dig, HMAC_SIZE,
                            this->user_hmac.dig, HMAC_SIZE );
  return true;
}

void
UserHmacData::calc_hello_key( ServiceBuf &svc,  HashDigest &ha ) noexcept
{
  PolyHmacDigest svc_hmac;
  ha.kdf_bytes( svc.pub_der, svc.pub_der_len );
  svc_hmac.calc_2( ha, svc.service, svc.service_len, 
                       svc.create, svc.create_len );
  ha.kdf_bytes( svc_hmac.dig, HMAC_SIZE,
                this->user_hmac.dig, HMAC_SIZE );
}

static void
print_pkerr( size_t pri_len,  size_t pub_len ) noexcept
{
  if ( pri_len == 0 || pub_len == 0 ) {
    if ( pri_len == 0 )
      fprintf( stderr, "The private key is not present\n" );
    if ( pub_len == 0 )
      fprintf( stderr, "The public key is not present\n" );
  }
  else {
    fprintf( stderr, "The password set may be incorrect\n" );
  }
}

bool
UserBuf::test_user( const CryptPass &pwd,  const ConfigTree::User &u ) noexcept
{
  OpenSsl_ECDH ec;
  UserBuf user( u );

  if ( ! user.get_ecdh( pwd, ec, DO_PUB ) ) {
    fprintf( stderr, "Unable to get public key for user \"%.*s\"\n",
             (int) user.user_len, user.user );
    print_pkerr( user.pri_len, user.pub_len );
    return false;
  }
  if ( ! user.get_ecdh( pwd, ec, DO_PRI ) ) {
    fprintf( stderr, "Unable to get private key for user \"%.*s\"\n",
             (int) user.user_len, user.user );
    print_pkerr( user.pri_len, user.pub_len );
    fprintf( stderr, "Need a private key in order to verify authentication\n" );
    return false;
  }
  return true;
}

/* append user to users */
void
ServiceBuf::add_user( const UserBuf &u ) noexcept
{
  this->users.push_tl( new ( ::malloc( sizeof( UserElem ) ) )
                       UserElem( u ) );
  if ( u.revoke_len != 0 )
    this->revoke.push_tl( new ( ::malloc( sizeof( RevokeElem ) ) )
                          RevokeElem( this->users.tl ) );
}

void
ServiceBuf::add_user( const UserElem &u ) noexcept
{
  this->users.push_tl( new ( ::malloc( sizeof( UserElem ) ) )
                       UserElem( u ) );
  if ( u.revoke != NULL )
    this->revoke.push_tl( new ( ::malloc( sizeof( RevokeElem ) ) )
                          RevokeElem( this->users.tl, u.revoke ) );
}

void
ServiceBuf::add_user( const ConfigTree::User &u ) noexcept
{
  this->users.push_tl( new ( ::malloc( sizeof( UserElem ) ) )
                       UserElem( u ) );
  if ( u.revoke.len != 0 )
    this->revoke.push_tl( new ( ::malloc( sizeof( RevokeElem ) ) )
                          RevokeElem( this->users.tl ) );
}

bool
ServiceBuf::gen_key( const char *svc,  size_t slen,
                     const CryptPass &pwd ) noexcept
{
  copy_max( this->service, this->service_len, MAX_SERVICE_LEN, svc, slen );
  this->create_len = timestamp_now( this->create, sizeof( this->create ) );

  OpenSsl_RSA rsa;
  if ( ! rsa.gen_key() )
    return false;
  if ( ! this->put_rsa( pwd, rsa, DO_BOTH ) )
    return false;
  return true;
}

bool
ServiceBuf::sign_users( OpenSsl_RSA *rsa,  const CryptPass &pwd ) noexcept
{
  OpenSsl_ECDH   ec;
  OpenSsl_RSA    rsa_buf;
  PolyHmacDigest hmac;
  uint64_t       ctr;
  HmacEncrypt< MAX_RSA_CIPHER_SIGN_LEN, MAX_RSA_SIGN_LEN > sig( ctr );

  if ( rsa == NULL ) {
    if ( ! this->get_rsa( pwd, rsa_buf, DO_BOTH ) ) {
      fprintf( stderr, "Unable to get keys for svc \"%.*s\"\n",
               (int) this->service_len, this->service );
      print_pkerr( this->pri_len, this->pub_len );
      return false;
    }
    rsa = &rsa_buf;
  }
  sig.init_kdf( *this, pwd );
  ctr  = aes_ctr_off( MAX_RSA_DER_PUB_LEN );
  ctr += aes_ctr_off( MAX_RSA_DER_PRI_LEN );

  /* sort them so the order can be recreated */
  this->users.sort<cmp_user_elem>();
  this->revoke.sort<cmp_revoke_elem>();
  /* get the hmacs and sign them */
  for ( UserElem *u = this->users.hd; u != NULL; u = u->next ) {
    UserHmacData data( u->user );
    if ( ! data.decrypt( pwd, DO_PUB ) )
      return false;

    sig.plain_len = sizeof( sig.plain );
    if ( ! rsa->sign_msg( data.user_hmac.digest(), HMAC_SIZE, sig.plain,
                          sig.plain_len ) ) {
      fprintf( stderr, "Unable to sign hmac\n" );
      return false;
    }
    u->sig_len = sizeof( u->sig );
    if ( ! sig.encrypt( u->sig, u->sig_len ) )
      return false;
    ctr += aes_ctr_off( MAX_RSA_SIGN_LEN );

    if ( u->revoke != NULL ) {
      RevokeElem * r = u->revoke;
      sig.plain_len = sizeof( sig.plain );
      if ( ! rsa->sign_msg( data.revoke_hmac.digest(), HMAC_SIZE, sig.plain,
                            sig.plain_len ) ) {
        fprintf( stderr, "Unable to sign hmac\n" );
        return false;
      }
      r->sig_len = sizeof( r->sig );
      if ( ! sig.encrypt( r->sig, r->sig_len ) )
        return false;
      ctr += aes_ctr_off( MAX_RSA_SIGN_LEN );
    }
  }
  return true;
}

bool
ServiceBuf::put_rsa( const CryptPass &pwd,  OpenSsl_RSA &rsa,
                     WhichPubPri put_op ) noexcept
{
  uint64_t ctr = 0;
  HmacEncrypt< MAX_RSA_CIPHER_PRI_LEN, MAX_RSA_DER_PRI_LEN > der( ctr );

  der.init_kdf( *this, pwd );
  if ( (put_op & DO_PUB) != 0 ) {
    if ( ! rsa.i2d_public( der.plain, der.plain_len ) )
      return false;
    this->pub_len = sizeof( this->pub );
    if ( ! der.encrypt( this->pub, this->pub_len ) )
      return false;
  }
  if ( (put_op & DO_PRI) != 0 ) {
    if ( ! rsa.i2d_private( der.plain, der.plain_len ) ) /* encode to der */
      return false;
    ctr = aes_ctr_off( MAX_RSA_DER_PUB_LEN );
    this->pri_len = sizeof( this->pri );
    if ( ! der.encrypt( this->pri, this->pri_len ) )
      return false;
  }
  return true;
}

void
ServiceBuf::copy( const ServiceBuf &svc ) noexcept
{
  size_t hdr_size = ( ( (uint8_t *) (void *) &this->users ) -
                      ( (uint8_t *) (void *) this ) );
  ::memcpy( (void *) this, (void *) &svc, hdr_size );
  for ( UserElem *u = svc.users.hd; u != NULL; u = u->next )
    this->add_user( *u );
}

void
ServiceBuf::load_service( const ConfigTree &tree,
                          const ConfigTree::Service &s ) noexcept
{
  uint32_t user_cnt = 0;

  this->release();
  this->copy( s );
  for ( const ConfigTree::User *u = tree.users.hd; u != NULL;
        u = u->next ) {
    if ( u->svc.equals( s.svc ) ) {
      this->add_user( *u );
      user_cnt++;
    }
  }
  if ( user_cnt == 0 )
    return;

  this->users.sort<cmp_user_elem>();
  this->revoke.sort<cmp_revoke_elem>();
  ConfigTree::StringPair * p = s.users.hd;
  for ( UserElem *el = this->users.hd; el != NULL; el = el->next ) {
    if ( p == NULL || cmp_bytes( p->name.val, p->name.len,
                                 el->user.user, el->user.user_len ) != 0 ) {
      fprintf( stderr, "Missing user \"%.*s\" signature\n",
               (int) el->user.user_len, el->user.user );
    }
    else {
      copy_max( el->sig, el->sig_len, MAX_RSA_CIPHER_SIGN_B64_LEN,
                p->value.val, p->value.len );
      p = p->next;
    }
  }
  for ( ; p != NULL; p = p->next ) {
    fprintf( stderr, "Missing service user \"%.*s\"\n",
             (int) p->name.len, p->name.val );
  }
  p = s.revoke.hd;
  for ( RevokeElem *re = this->revoke.hd; re != NULL; re = re->next ) {
    if ( p == NULL || cmp_bytes( p->name.val, p->name.len,
                                 re->user->user.user,
                                 re->user->user.user_len ) != 0 ) {
      fprintf( stderr, "Missing user \"%.*s\" revoke signature\n",
               (int) re->user->user.user_len, re->user->user.user );
    }
    else {
      copy_max( re->sig, re->sig_len, MAX_RSA_CIPHER_SIGN_B64_LEN,
                p->value.val, p->value.len );
      p = p->next;
    }
  }
  for ( ; p != NULL; p = p->next ) {
    fprintf( stderr, "Missing revoke user \"%.*s\"\n",
             (int) p->name.len, p->name.val );
  }
}

bool
ServiceBuf::check_signatures( const CryptPass &pwd ) noexcept
{
  OpenSsl_ECDH   ec;
  OpenSsl_RSA    rsa;
  PolyHmacDigest hmac;
  uint64_t       ctr;
  HmacDecrypt< MAX_RSA_CIPHER_SIGN_LEN, MAX_RSA_SIGN_LEN > sig( ctr );

  if ( ! this->get_rsa( pwd, rsa, DO_PUB ) ) {
    fprintf( stderr, "Unable to get keys for svc \"%.*s\"\n",
             (int) this->service_len, this->service );
    print_pkerr( this->pri_len, this->pub_len );
    return false;
  }
  sig.init_kdf( *this, pwd );
  ctr  = aes_ctr_off( MAX_RSA_DER_PUB_LEN );
  ctr += aes_ctr_off( MAX_RSA_DER_PRI_LEN );

  for ( UserElem *u = this->users.hd; u != NULL; u = u->next ) {
    UserHmacData data( u->user );
    if ( ! data.decrypt( pwd, DO_PUB ) )
      return false;

    if ( ! sig.decrypt( u->user, u->sig, u->sig_len ) )
      return false;

    if ( ! rsa.verify_msg( data.user_hmac.digest(), HMAC_SIZE, sig.plain,
                           sig.plain_len ) ) {
      fprintf( stderr, "Verify user sig \"%.*s\" failed\n",
               (int) u->user.user_len, u->user.user );
      return false;
    }
    ctr += aes_ctr_off( MAX_RSA_SIGN_LEN );

    if ( u->revoke != NULL ) {
      RevokeElem *r = u->revoke;

      if ( ! sig.decrypt( u->user, r->sig, r->sig_len ) )
        return false;

      if ( ! rsa.verify_msg( data.revoke_hmac.digest(), HMAC_SIZE, sig.plain,
                             sig.plain_len ) ) {
        fprintf( stderr, "Verify revoke user sig \"%.*s\" failed\n",
                 (int) u->user.user_len, u->user.user );
        return false;
      }
      ctr += aes_ctr_off( MAX_RSA_SIGN_LEN );
    }
  }
  return true;
}

void
ServiceBuf::copy( const ConfigTree::Service &s ) noexcept
{
  copy_max( this->service, this->service_len, MAX_SERVICE_LEN, s.svc.val,
            s.svc.len );
  copy_max( this->create, this->create_len, MAX_TIME_LEN, s.create.val,
            s.create.len );
  copy_max( this->pri, this->pri_len, MAX_RSA_CIPHER_PRI_B64_LEN,
            s.pri.val, s.pri.len );
  copy_max( this->pub, this->pub_len, MAX_RSA_CIPHER_PUB_B64_LEN,
            s.pub.val, s.pub.len );
  if ( this->pri_len == 0 )
    this->pri[ 0 ] = '\0';
  if ( this->pub_len == 0 )
    this->pub[ 0 ] = '\0';
  if ( this->pri_len != s.pri.len )
    fprintf( stderr, "pri len %u > %lu\n", s.pri.len,
             MAX_RSA_CIPHER_PRI_B64_LEN );
  if ( this->pub_len != s.pub.len )
    fprintf( stderr, "pub len %u > %lu\n", s.pub.len,
             MAX_RSA_CIPHER_PUB_B64_LEN );
}

bool
ServiceBuf::get_rsa( const CryptPass &pwd,  OpenSsl_RSA &rsa,
                     WhichPubPri get_op ) noexcept
{
  uint64_t ctr = 0;
  HmacDecrypt< MAX_RSA_CIPHER_PRI_LEN, MAX_RSA_DER_PRI_LEN > der( ctr );
  der.init_kdf( *this, pwd );

  if ( (get_op & DO_PUB) != 0 ) {
    if ( this->pub_len == 0 )
      return false;
    if ( ! der.decrypt( *this, this->pub, this->pub_len ) )
      return false;
    if ( ! rsa.d2i_public( der.plain, der.plain_len ) ) {
      fprintf( stderr, "Unable to import public key\n" );
      return false;
    }
    ::memcpy( this->pub_der, der.plain, der.plain_len );
    this->pub_der_len = der.plain_len;
  }
  if ( (get_op & DO_PRI) != 0 ) {
    if ( this->pri_len == 0 )
      return false;
    ctr += aes_ctr_off( MAX_RSA_DER_PUB_LEN );
    if ( ! der.decrypt( *this, this->pri, this->pri_len ) )
      return false;
    if ( ! rsa.d2i_private( der.plain, der.plain_len ) ) {
      fprintf( stderr, "Unable to import private key\n" );
      return false;
    }
  }
  return true;
}

bool
UserBuf::change_pass( const CryptPass &old_pwd,
                      const CryptPass &new_pwd ) noexcept
{
  OpenSsl_ECDH ec;
  bool    has_pri = false;

  if ( ! this->get_ecdh( old_pwd, ec, DO_PUB ) ) {
    fprintf( stderr, "Unable to get public key for user \"%.*s\"\n",
             (int) this->user_len, this->user );
    print_pkerr( this->pri_len, this->pub_len );
    return false;
  }
  if ( this->pri_len != 0 ) {
    has_pri = true;
    if ( ! this->get_ecdh( old_pwd, ec, DO_PRI ) ) {
      fprintf( stderr, "Unable to get private key for user \"%.*s\"\n",
               (int) this->user_len, this->user );
      print_pkerr( this->pri_len, this->pub_len );
      return false;
    }
  }
  WhichPubPri op = ( has_pri ? DO_BOTH : DO_PUB );
  if ( ! this->put_ecdh( new_pwd, ec, op ) )
    return false;
  return true;
}

bool
ServiceBuf::change_pass( const CryptPass &old_pwd,
                         const CryptPass &new_pwd ) noexcept
{
  uint64_t    ctr;
  HmacDecrypt< MAX_RSA_CIPHER_SIGN_LEN, MAX_RSA_SIGN_LEN > old_sig( ctr );
  HmacEncrypt< MAX_RSA_CIPHER_SIGN_LEN, MAX_RSA_SIGN_LEN > new_sig( ctr );
  OpenSsl_RSA rsa;
  bool        has_pri = false;

  if ( ! this->get_rsa( old_pwd, rsa, DO_PUB ) ) {
    fprintf( stderr, "Unable to get public key for svc \"%.*s\"\n",
             (int) this->service_len, this->service );
    print_pkerr( this->pri_len, this->pub_len );
    return false;
  }
  if ( this->pri_len != 0 ) {
    has_pri = true;
    if ( ! this->get_rsa( old_pwd, rsa, DO_PRI ) ) {
      fprintf( stderr, "Unable to get private key for svc \"%.*s\"\n",
               (int) this->service_len, this->service );
      print_pkerr( this->pri_len, this->pub_len );
      return false;
    }
  }
  old_sig.init_kdf( *this, old_pwd );
  new_sig.init_kdf( *this, new_pwd );

  ctr  = aes_ctr_off( MAX_RSA_DER_PUB_LEN );
  ctr += aes_ctr_off( MAX_RSA_DER_PRI_LEN );

  for ( UserElem *u = this->users.hd; u != NULL; u = u->next ) {
    if ( ! old_sig.decrypt( u->user, u->sig, u->sig_len ) )
      return false;

    ::memcpy( new_sig.plain, old_sig.plain, old_sig.plain_len );
    new_sig.plain_len = old_sig.plain_len;
    u->sig_len = sizeof( u->sig );
    if ( ! new_sig.encrypt( u->sig, u->sig_len ) )
      return false;
    ctr += aes_ctr_off( MAX_RSA_SIGN_LEN );

    if ( u->revoke != NULL ) {
      RevokeElem *r = u->revoke;
      if ( ! old_sig.decrypt( u->user, r->sig, r->sig_len ) )
        return false;

      ::memcpy( new_sig.plain, old_sig.plain, old_sig.plain_len );
      new_sig.plain_len = old_sig.plain_len;
      r->sig_len = sizeof( r->sig );
      if ( ! new_sig.encrypt( r->sig, r->sig_len ) )
        return false;
      ctr += aes_ctr_off( MAX_RSA_SIGN_LEN );
    }

    if ( ! u->user.change_pass( old_pwd, new_pwd ) ) {
      fprintf( stderr, "Unable to change user \"%.*s\"\n",
               (int) u->user.user_len, u->user.user );
      return false;
    }
  }
  WhichPubPri op = ( has_pri ? DO_BOTH : DO_PUB );
  if ( ! this->put_rsa( new_pwd, rsa, op ) )
    return false;
  return true;
}

bool
ServiceBuf::revoke_user( const char *user,  size_t user_len ) noexcept
{
  size_t match_count = 0;
  for ( UserElem *u = this->users.hd; u != NULL; u = u->next ) {
    if ( cmp_bytes( u->user.user, u->user.user_len, user, user_len ) == 0 ) {
      if ( u->revoke == NULL ) {
        u->user.revoke_len = timestamp_now( u->user.revoke,
                                            sizeof( u->user.revoke ) );
        this->revoke.push_tl( new ( ::malloc( sizeof( RevokeElem ) ) )
                              RevokeElem( u ) );
      }
      match_count++;
    }
  }
  return match_count > 0;
}

bool
ServiceBuf::remove_user( const char *user,  size_t user_len ) noexcept
{
  UserList   tmp;
  RevokeList tmpr;
  size_t     rev_count = 0;

  if ( ! this->users.is_empty() ) {
    UserElem * last = NULL,
             * next,
             * u;
    for ( u = this->users.hd; u != NULL; u = next ) {
      next = u->next;
      if ( cmp_bytes( u->user.user, u->user.user_len, user, user_len ) == 0 ) {
        if ( last == NULL )
          this->users.hd = next;
        else
          last->next = next;
        if ( u->revoke != NULL ) {
          u->revoke = NULL;
          rev_count++;
        }
        tmp.push_tl( u );
      }
      else {
        last = u;
      }
    }
  }
  if ( tmp.hd == NULL )
    return false;
  if ( rev_count > 0 ) {
    RevokeElem * last = NULL,
               * next,
               * r;
    for ( r = this->revoke.hd; r != NULL; r = next ) {
      next = r->next;
      if ( r->user->revoke == NULL ) {
        if ( last == NULL )
          this->revoke.hd = next;
        else
          last->next = next;
        tmpr.push_tl( r );
        if ( --rev_count == 0 )
          break;
      }
      else {
        last = r;
      }
    }
  }
  while ( ! tmp.is_empty() )
    delete tmp.pop_hd();
  while ( ! tmpr.is_empty() )
    delete tmpr.pop_hd();
  return true;
}

static FILE *
open_out_file( const char *fn ) noexcept
{
  if ( fn == NULL )
    return stdout;
  FILE *fp = ::fopen( fn, "w" );
  if ( fp == NULL )
    ::perror( fn );
  return fp;
}

static void
close_out_file( FILE *fp ) noexcept
{
  if ( fp != NULL && fp != stdout )
    ::fclose( fp );
}

static void
print_yaml2( const UserBuf &u,  int indent,  FILE *out,
             bool include_pri ) noexcept
{
  fprintf( out,
  "%*s%suser: \"%.*s\"\n"
  "%*ssvc: \"%.*s\"\n"
  "%*screate: \"%.*s\"\n",
  ( indent > 2 ? indent - 2 : 0 ), "", ( indent > 0 ? "- " : "" ),
  (int) u.user_len, u.user,
  indent, "", (int) u.service_len, u.service,
  indent, "", (int) u.create_len, u.create );
  if ( u.expires_len > 0 )
    fprintf( out, "%*sexpires: \"%.*s\"\n", indent, "",
            (int) u.expires_len, u.expires );
  if ( u.revoke_len > 0 )
    fprintf( out, "%*srevoke: \"%.*s\"\n", indent, "",
            (int) u.revoke_len, u.revoke );
  if ( u.pri_len > 0 && include_pri )
    fprintf( out, "%*spri: \"%.*s\"\n", indent, "",
            (int) u.pri_len, u.pri );
  if ( u.pub_len > 0 )
    fprintf( out, "%*spub: \"%.*s\"\n", indent, "",
            (int) u.pub_len, u.pub );
}

bool
UserBuf::print_yaml( int indent,  const char *fn,  bool include_pri ) noexcept
{
  FILE *out = open_out_file( fn );
  if ( out == NULL )
    return false;
  print_yaml2( *this, indent, out, include_pri );
  close_out_file( out );
  return true;
}

bool
UserElem::print_yaml( const char *fn,  bool include_pri ) noexcept
{
  return this->user.print_yaml( 0, fn, include_pri );
}

bool
UserElem::print_yaml_count( const char *fn,  bool include_pri,
                            size_t count ) noexcept
{
  if ( count == 1 )
    return this->print_yaml( fn, include_pri );
  FILE *out = open_out_file( fn );
  if ( out == NULL )
    return false;

  fprintf( out, "users:\n" );
  for ( UserElem *el = this; count > 0; el = el->next ) {
    print_yaml2( el->user, 4, out, include_pri );
    count--;
  }

  close_out_file( out );
  return true;
  
}

bool
ServiceBuf::print_yaml( int indent,  const char *fn,
                        bool include_pri ) noexcept
{
  FILE *out = open_out_file( fn );
  if ( out == NULL )
    return false;
  fprintf( out,
  "%*s%ssvc: \"%.*s\"\n"
  "%*screate: \"%.*s\"\n",
  ( indent > 2 ? indent - 2 : 0 ), "", ( indent > 0 ? "- " : "" ),
  (int) this->service_len, this->service,
  indent, "", (int) this->create_len, this->create );
  if ( this->pri_len > 0 && include_pri )
    fprintf( out, "%*spri: \"%.*s\"\n", indent, "",
            (int) this->pri_len, this->pri );
  if ( this->pub_len > 0 )
    fprintf( out, "%*spub: \"%.*s\"\n", indent, "",
            (int) this->pub_len, this->pub );
  if ( this->users.hd != NULL ) {
    fprintf( out, "%*susers:\n", indent, "" );
    for ( UserElem *u = this->users.hd; u != NULL; u = u->next ) {
      fprintf( out, "%*s  \"%.*s\": \"%.*s\"\n",
              indent, "", (int) u->user.user_len, u->user.user,
              (int) u->sig_len, u->sig );
    }
  }
  if ( this->revoke.hd != NULL ) {
    fprintf( out, "%*srevoke:\n", indent, "" );
    for ( RevokeElem *r = this->revoke.hd; r != NULL; r = r->next ) {
      fprintf( out, "%*s  \"%.*s\" : \"%.*s\"\n",
              indent, "", (int) r->user->user.user_len, r->user->user.user,
              (int) r->sig_len, r->sig );
    }
  }
  close_out_file( out );
  return true;
}


static void
print_json2( const UserBuf &u,  int indent,  char sep,  FILE *out,
             bool include_pri ) noexcept
{
  char sep_s[ 2 ] = { sep, 0 };
  fprintf( out,
  "%*s{\n"
  "%*s  \"user\" : \"%.*s\",\n"
  "%*s  \"svc\" : \"%.*s\",\n"
  "%*s  \"create\" : \"%.*s\"",
  indent, "",
  indent, "", (int) u.user_len, u.user,
  indent, "", (int) u.service_len, u.service,
  indent, "", (int) u.create_len, u.create );
  if ( u.expires_len > 0 )
    fprintf( out, ",\n%*s  \"expires\" : \"%.*s\"", indent, "",
            (int) u.expires_len, u.expires );
  if ( u.revoke_len > 0 )
    fprintf( out, ",\n%*s  \"revoke\" : \"%.*s\"", indent, "",
            (int) u.revoke_len, u.revoke );
  if ( u.pri_len > 0 && include_pri )
    fprintf( out, ",\n%*s  \"pri\" : \"%.*s\"", indent, "",
            (int) u.pri_len, u.pri );
  if ( u.pub_len > 0 )
    fprintf( out, ",\n%*s  \"pub\" : \"%.*s\"", indent, "",
            (int) u.pub_len, u.pub );
  fprintf( out, "\n%*s}%s\n", indent, "", sep_s );
}

bool
UserBuf::print_json( int indent,  char sep,  const char *fn,
                     bool include_pri ) noexcept
{
  FILE *out = open_out_file( fn );
  if ( out == NULL )
    return false;
  print_json2( *this, indent, sep, out, include_pri );
  close_out_file( out );
  return true;
}

bool
UserElem::print_json( const char *fn,  bool include_pri ) noexcept
{
  return this->user.print_json( 0, 0, fn, include_pri );
}

bool
UserElem::print_json_count( const char *fn,  bool include_pri,
                            size_t count ) noexcept
{
  if ( count == 1 )
    return this->print_json( fn, include_pri );
  FILE *out = open_out_file( fn );
  if ( out == NULL )
    return false;

  fprintf( out, "{\n  \"users\" : [\n" );
  for ( UserElem *el = this; count > 0; el = el->next ) {
    print_json2( el->user, 4, ( count > 1 ? ',' : 0 ), out, include_pri );
    count--;
  }
  fprintf( out, "  ]\n}\n" );

  close_out_file( out );
  return true;
  
}

bool
ServiceBuf::print_json( int indent,  char sep,  const char *fn,
                        bool include_pri ) noexcept
{
  FILE *out = open_out_file( fn );
  if ( out == NULL )
    return false;
  char sep_s[ 2 ] = { sep, 0 };
  fprintf( out,
  "%*s{\n"
  "%*s  \"svc\" : \"%.*s\",\n"
  "%*s  \"create\" : \"%.*s\"",
  indent, "",
  indent, "", (int) this->service_len, this->service,
  indent, "", (int) this->create_len, this->create );
  if ( this->pri_len > 0 && include_pri )
    fprintf( out, ",\n%*s  \"pri\" : \"%.*s\"", indent, "",
            (int) this->pri_len, this->pri );
  if ( this->pub_len > 0 )
    fprintf( out, ",\n%*s  \"pub\" : \"%.*s\"", indent, "",
            (int) this->pub_len, this->pub );
  if ( this->users.hd != NULL ) {
    fprintf( out, ",\n%*s  \"users\" : {\n", indent, "" );
    for ( UserElem *u = this->users.hd; u != NULL; u = u->next ) {
      if ( u != this->users.hd )
        fprintf( out, ",\n" );
      fprintf( out, "%*s    \"%.*s\" : \"%.*s\"",
              indent, "", (int) u->user.user_len, u->user.user,
              (int) u->sig_len, u->sig );
    }
    fprintf( out, "\n%*s  }", indent, "" );
  }
  if ( this->revoke.hd != NULL ) {
    fprintf( out, ",\n%*s  \"revoke\" : {\n", indent, "" );
    for ( RevokeElem *r = this->revoke.hd; r != NULL; r = r->next ) {
      if ( r != this->revoke.hd )
        fprintf( out, ",\n" );
      fprintf( out, "%*s    \"%.*s\" : \"%.*s\"",
              indent, "", (int) r->user->user.user_len, r->user->user.user,
              (int) r->sig_len, r->sig );
    }
    fprintf( out, "\n%*s  }", indent, "" );
  }
  fprintf( out, "\n%*s}%s\n", indent, "", sep_s );
  close_out_file( out );
  return true;
}

