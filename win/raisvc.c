/* raisvc.c -- run a console program as a Windows service (the systemd unit
 * of the windows distribution).  Built with mingw:
 *   x86_64-w64-mingw32-gcc -O2 -o raisvc.exe raisvc.c -ladvapi32
 *
 *   raisvc install <name> [-w workdir] [-l logfile] [-D "description"]
 *                  [-a auto|manual] -- <program> [args ...]
 *   raisvc uninstall <name>
 *   raisvc start <name> | stop <name> | status <name>
 *   raisvc run <name>            (what the service control manager invokes)
 *
 * install writes the command line, working directory and log file to
 * HKLM\SOFTWARE\RaiTechnology\raisvc\<name> and creates the service with
 *   binPath = "<this exe>" run <name>
 * plus restart-on-failure (5s), like Restart=always / RestartSec=5.
 * run: registers with the SCM, starts the program with stdout/stderr
 * appended to the log file, reports RUNNING, and on STOP sends the program a
 * CTRL_BREAK, waits up to 20s, then terminates it.  If the program exits by
 * itself the service reports the exit code and stops (the SCM restarts it).
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REG_ROOT "SOFTWARE\\RaiTechnology\\raisvc\\"
#define MAXCMD   8192

static SERVICE_STATUS_HANDLE svc_status;
static HANDLE                svc_stop_event;
static PROCESS_INFORMATION   child;
static char                  svc_name[ 256 ];

static void
report( DWORD state,  DWORD exit_code,  DWORD wait_hint )
{
  SERVICE_STATUS st;
  memset( &st, 0, sizeof( st ) );
  st.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
  st.dwCurrentState            = state;
  st.dwControlsAccepted        = ( state == SERVICE_START_PENDING ) ? 0 :
                                 SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  st.dwWin32ExitCode           = exit_code == 0 ? NO_ERROR
                                                : ERROR_SERVICE_SPECIFIC_ERROR;
  st.dwServiceSpecificExitCode = exit_code;
  st.dwWaitHint                = wait_hint;
  SetServiceStatus( svc_status, &st );
}

static int
reg_get( const char *name,  const char *key,  char *buf,  DWORD len )
{
  char path[ 512 ];
  HKEY h;
  DWORD type = REG_SZ;
  snprintf( path, sizeof( path ), REG_ROOT "%s", name );
  if ( RegOpenKeyExA( HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &h ) != 0 )
    return -1;
  buf[ 0 ] = '\0';
  int r = RegQueryValueExA( h, key, NULL, &type, (BYTE *) buf, &len ) == 0 ? 0 : -1;
  RegCloseKey( h );
  return r;
}

static int
reg_set( const char *name,  const char *key,  const char *val )
{
  char path[ 512 ];
  HKEY h;
  snprintf( path, sizeof( path ), REG_ROOT "%s", name );
  if ( RegCreateKeyExA( HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_WRITE, NULL,
                        &h, NULL ) != 0 )
    return -1;
  int r = RegSetValueExA( h, key, 0, REG_SZ, (const BYTE *) val,
                          (DWORD) strlen( val ) + 1 ) == 0 ? 0 : -1;
  RegCloseKey( h );
  return r;
}

static void
win_error( const char *what )
{
  char  msg[ 512 ];
  DWORD e = GetLastError();
  FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, e, 0, msg, sizeof( msg ), NULL );
  fprintf( stderr, "%s: (%lu) %s", what, (unsigned long) e, msg );
}

/* ---- the service itself ------------------------------------------------ */
static int
start_child( void )
{
  char cmd[ MAXCMD ], wkdir[ MAX_PATH ], logf[ MAX_PATH ];
  STARTUPINFOA si;
  HANDLE log = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES sa = { sizeof( sa ), NULL, TRUE };

  if ( reg_get( svc_name, "Command", cmd, sizeof( cmd ) ) != 0 )
    return -1;
  reg_get( svc_name, "WorkDir", wkdir, sizeof( wkdir ) );
  reg_get( svc_name, "LogFile", logf, sizeof( logf ) );

  memset( &si, 0, sizeof( si ) );
  si.cb = sizeof( si );
  if ( logf[ 0 ] != '\0' ) {
    log = CreateFileA( logf, FILE_APPEND_DATA, FILE_SHARE_READ, &sa,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( log != INVALID_HANDLE_VALUE ) {
      si.dwFlags   = STARTF_USESTDHANDLES;
      si.hStdInput = GetStdHandle( STD_INPUT_HANDLE );
      si.hStdOutput = log;
      si.hStdError  = log;
    }
  }
  memset( &child, 0, sizeof( child ) );
  BOOL ok = CreateProcessA( NULL, cmd, NULL, NULL, TRUE,
                            CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, NULL,
                            wkdir[ 0 ] ? wkdir : NULL, &si, &child );
  if ( log != INVALID_HANDLE_VALUE )
    CloseHandle( log );
  if ( ! ok )
    return -1;
  CloseHandle( child.hThread );
  return 0;
}

static BOOL WINAPI
ignore_ctrl( DWORD ctrl )
{
  (void) ctrl;
  return TRUE;     /* the break is for the child, not for us */
}

static void
stop_child( void )
{
  if ( child.hProcess == NULL )
    return;
  /* polite first: the program sees it as SIGINT-like (ctrl-break).
   * GenerateConsoleCtrlEvent only reaches processes on the caller's console
   * and a service has none (the child got its own hidden one from
   * CREATE_NO_WINDOW), so attach to the child's console for the duration --
   * otherwise the event is silently dropped and every stop waits out the
   * timeout below and ends in TerminateProcess */
  if ( AttachConsole( child.dwProcessId ) ) {
    SetConsoleCtrlHandler( ignore_ctrl, TRUE );
    GenerateConsoleCtrlEvent( CTRL_BREAK_EVENT, child.dwProcessId );
    FreeConsole();
  }
  if ( WaitForSingleObject( child.hProcess, 20000 ) != WAIT_OBJECT_0 )
    TerminateProcess( child.hProcess, 1 );
  CloseHandle( child.hProcess );
  child.hProcess = NULL;
}

static DWORD WINAPI
ctrl_handler( DWORD ctrl,  DWORD type,  LPVOID data,  LPVOID ctx )
{
  (void) type; (void) data; (void) ctx;
  switch ( ctrl ) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
      report( SERVICE_STOP_PENDING, 0, 25000 );
      SetEvent( svc_stop_event );
      return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI
service_main( DWORD argc,  LPSTR *argv )
{
  (void) argc; (void) argv;
  svc_status = RegisterServiceCtrlHandlerExA( svc_name, ctrl_handler, NULL );
  if ( svc_status == 0 )
    return;
  report( SERVICE_START_PENDING, 0, 5000 );
  svc_stop_event = CreateEvent( NULL, TRUE, FALSE, NULL );
  if ( start_child() != 0 ) {
    report( SERVICE_STOPPED, GetLastError() ? GetLastError() : 1, 0 );
    return;
  }
  report( SERVICE_RUNNING, 0, 0 );

  HANDLE waits[ 2 ] = { svc_stop_event, child.hProcess };
  DWORD  w = WaitForMultipleObjects( 2, waits, FALSE, INFINITE );
  DWORD  exit_code = 0;
  if ( w == WAIT_OBJECT_0 ) {          /* stop requested */
    stop_child();
  }
  else {                               /* program exited on its own */
    GetExitCodeProcess( child.hProcess, &exit_code );
    CloseHandle( child.hProcess );
    child.hProcess = NULL;
    if ( exit_code == 0 )
      exit_code = 1;                   /* so the SCM failure actions restart */
  }
  report( SERVICE_STOPPED, exit_code, 0 );
}

/* ---- install / uninstall / start / stop / status ------------------------ */
static int
do_install( int argc,  char **argv )
{
  const char *name = argv[ 2 ], *wkdir = "", *logf = "", *descr = NULL;
  DWORD start = SERVICE_AUTO_START;
  int i;
  char cmd[ MAXCMD ] = "", exe[ MAX_PATH ], bin[ MAX_PATH + 64 ];

  for ( i = 3; i < argc && strcmp( argv[ i ], "--" ) != 0; i++ ) {
    if ( strcmp( argv[ i ], "-w" ) == 0 && i + 1 < argc ) wkdir = argv[ ++i ];
    else if ( strcmp( argv[ i ], "-l" ) == 0 && i + 1 < argc ) logf = argv[ ++i ];
    else if ( strcmp( argv[ i ], "-D" ) == 0 && i + 1 < argc ) descr = argv[ ++i ];
    else if ( strcmp( argv[ i ], "-a" ) == 0 && i + 1 < argc )
      start = strcmp( argv[ ++i ], "manual" ) == 0 ? SERVICE_DEMAND_START
                                                   : SERVICE_AUTO_START;
    else { fprintf( stderr, "unknown option %s\n", argv[ i ] ); return 2; }
  }
  if ( i >= argc - 1 ) {
    fprintf( stderr, "install: missing -- <program> [args]\n" );
    return 2;
  }
  for ( i++; i < argc; i++ ) {          /* quote args with spaces */
    if ( cmd[ 0 ] ) strncat( cmd, " ", sizeof( cmd ) - strlen( cmd ) - 1 );
    if ( strchr( argv[ i ], ' ' ) ) {
      strncat( cmd, "\"", sizeof( cmd ) - strlen( cmd ) - 1 );
      strncat( cmd, argv[ i ], sizeof( cmd ) - strlen( cmd ) - 1 );
      strncat( cmd, "\"", sizeof( cmd ) - strlen( cmd ) - 1 );
    }
    else
      strncat( cmd, argv[ i ], sizeof( cmd ) - strlen( cmd ) - 1 );
  }
  GetModuleFileNameA( NULL, exe, sizeof( exe ) );
  snprintf( bin, sizeof( bin ), "\"%s\" run %s", exe, name );

  SC_HANDLE scm = OpenSCManagerA( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
  if ( scm == NULL ) { win_error( "OpenSCManager" ); return 1; }
  SC_HANDLE svc = NULL;
  for ( i = 0; i < 300; i++ ) {                /* up to 30s */
    svc = CreateServiceA( scm, name, descr ? descr : name,
                          SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                          start, SERVICE_ERROR_NORMAL, bin, NULL, NULL,
                          "Tcpip\0", NULL, NULL );
    if ( svc != NULL || GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE )
      break;
    Sleep( 100 );                              /* previous instance going away */
  }
  if ( svc == NULL ) { win_error( "CreateService" ); CloseServiceHandle( scm ); return 1; }
  if ( descr != NULL ) {
    SERVICE_DESCRIPTIONA d = { (LPSTR) descr };
    ChangeServiceConfig2A( svc, SERVICE_CONFIG_DESCRIPTION, &d );
  }
  /* Restart=always, RestartSec=5 */
  SC_ACTION acts[ 3 ] = { { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 5000 },
                          { SC_ACTION_RESTART, 60000 } };
  SERVICE_FAILURE_ACTIONSA fa = { 86400, NULL, NULL, 3, acts };
  ChangeServiceConfig2A( svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa );
  CloseServiceHandle( svc );
  CloseServiceHandle( scm );

  reg_set( name, "Command", cmd );
  reg_set( name, "WorkDir", wkdir );
  reg_set( name, "LogFile", logf );
  printf( "installed service %s\n  command: %s\n  workdir: %s\n  log:     %s\n",
          name, cmd, wkdir, logf );
  return 0;
}

static int
do_control( const char *op,  const char *name )
{
  SC_HANDLE scm = OpenSCManagerA( NULL, NULL, SC_MANAGER_CONNECT );
  if ( scm == NULL ) { win_error( "OpenSCManager" ); return 1; }
  SC_HANDLE svc = OpenServiceA( scm, name, SERVICE_ALL_ACCESS );
  if ( svc == NULL ) { win_error( "OpenService" ); CloseServiceHandle( scm ); return 1; }
  int r = 0;
  SERVICE_STATUS st;
  if ( strcmp( op, "uninstall" ) == 0 ) {
    int i;
    /* stop and wait for STOPPED, a service marked for deletion while it is
     * still running blocks CreateService of the same name (error 1072) */
    if ( ControlService( svc, SERVICE_CONTROL_STOP, &st ) ) {
      for ( i = 0; i < 300; i++ ) {          /* up to 30s */
        if ( ! QueryServiceStatus( svc, &st ) || st.dwCurrentState == SERVICE_STOPPED )
          break;
        Sleep( 100 );
      }
    }
    if ( ! DeleteService( svc ) ) { win_error( "DeleteService" ); r = 1; }
    else {
      char path[ 512 ];
      snprintf( path, sizeof( path ), REG_ROOT "%s", name );
      RegDeleteKeyA( HKEY_LOCAL_MACHINE, path );
      CloseServiceHandle( svc );
      svc = NULL;
      /* deletion completes when the last handle closes; wait until the
       * name is really gone so an immediate reinstall works */
      for ( i = 0; i < 300; i++ ) {
        SC_HANDLE h = OpenServiceA( scm, name, SERVICE_QUERY_STATUS );
        if ( h == NULL ) break;
        CloseServiceHandle( h );
        Sleep( 100 );
      }
      printf( "removed service %s\n", name );
    }
  }
  else if ( strcmp( op, "start" ) == 0 ) {
    if ( ! StartServiceA( svc, 0, NULL ) ) { win_error( "StartService" ); r = 1; }
    else printf( "%s started\n", name );
  }
  else if ( strcmp( op, "stop" ) == 0 ) {
    if ( ! ControlService( svc, SERVICE_CONTROL_STOP, &st ) ) { win_error( "ControlService" ); r = 1; }
    else {
      int i;
      /* wait for STOPPED, the exe and dlls of the program stay locked until
       * it is gone and an installer that overwrites them next skips them */
      for ( i = 0; i < 300; i++ ) {          /* up to 30s */
        if ( ! QueryServiceStatus( svc, &st ) || st.dwCurrentState == SERVICE_STOPPED )
          break;
        Sleep( 100 );
      }
      if ( st.dwCurrentState == SERVICE_STOPPED ) printf( "%s stopped\n", name );
      else { printf( "%s still stopping\n", name ); r = 1; }
    }
  }
  else if ( strcmp( op, "status" ) == 0 ) {
    if ( ! QueryServiceStatus( svc, &st ) ) { win_error( "QueryServiceStatus" ); r = 1; }
    else {
      const char *s = st.dwCurrentState == SERVICE_RUNNING ? "running" :
                      st.dwCurrentState == SERVICE_STOPPED ? "stopped" :
                      st.dwCurrentState == SERVICE_START_PENDING ? "starting" :
                      st.dwCurrentState == SERVICE_STOP_PENDING ? "stopping" : "?";
      char cmd[ MAXCMD ] = "";
      reg_get( name, "Command", cmd, sizeof( cmd ) );
      printf( "%s: %s (exit %lu)\n  command: %s\n", name, s,
              (unsigned long) st.dwServiceSpecificExitCode, cmd );
      r = st.dwCurrentState == SERVICE_RUNNING ? 0 : 3;
    }
  }
  if ( svc != NULL )
    CloseServiceHandle( svc );
  CloseServiceHandle( scm );
  return r;
}

int
main( int argc,  char **argv )
{
  if ( argc >= 3 && strcmp( argv[ 1 ], "run" ) == 0 ) {
    strncpy( svc_name, argv[ 2 ], sizeof( svc_name ) - 1 );
    SERVICE_TABLE_ENTRYA table[] = { { svc_name, service_main }, { NULL, NULL } };
    if ( ! StartServiceCtrlDispatcherA( table ) ) {
      win_error( "StartServiceCtrlDispatcher (run is for the service manager)" );
      return 1;
    }
    return 0;
  }
  if ( argc >= 3 && strcmp( argv[ 1 ], "install" ) == 0 )
    return do_install( argc, argv );
  if ( argc >= 3 && ( strcmp( argv[ 1 ], "uninstall" ) == 0 ||
                      strcmp( argv[ 1 ], "start" ) == 0 ||
                      strcmp( argv[ 1 ], "stop" ) == 0 ||
                      strcmp( argv[ 1 ], "status" ) == 0 ) )
    return do_control( argv[ 1 ], argv[ 2 ] );
  fprintf( stderr,
    "raisvc: run a program as a windows service\n"
    "  raisvc install <name> [-w workdir] [-l logfile] [-D descr] [-a auto|manual] -- <program> [args]\n"
    "  raisvc uninstall <name>\n"
    "  raisvc start|stop|status <name>\n" );
  return 2;
}
