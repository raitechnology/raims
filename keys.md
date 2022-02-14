# Rai MS Key Configuration

The key configuration files are necessary to join the network.  They authenticate
peers and the message traffic that flows between peers.  It does not authenticate
the local bridging protocols RV, NATS, or Redis.

Generating a master config is done with the `ms_gen_key` program.  The default location
for the config directory is `./config`, other locations are specified with the `-d`
option.

Initially, the config directory is empty.  Intialize with some users and a service name.

  ```
  $ ms_gen_key -u A B C -s test
  create dir  config                          -- the configure directory
  create file config/.salt                    -- generate new salt
  create file config/.pass                    -- generated a new password
  create file config/config.yaml              -- base include file
  create file config/param.yaml               -- parameters file
  create file config/svc_test.yaml            -- defines the service and signs users
  create file config/user_A_svc_test.yaml     -- defines the user
  create file config/user_B_svc_test.yaml     -- defines the user
  create file config/user_C_svc_test.yaml     -- defines the user
  OK? y
  done
  ```

Exporting the keys for each of the nodes causes the `.pass` file the change and the
unnecessary private keys to be removed.  The only private key that remains, is for the
peer.  This trimmed configuration allows the peer to run, but not generate new peers
because the private key of the service is not present.

  ```
  $ ms_gen_key -x A B C -s test
  - Loading service "test"               
  - Signatures ok                        
  create dir  A                          -- exported configure directory
  create file A/.salt                    -- a copy of salt
  create file A/.pass                    -- generated a new password
  create file A/param.yaml               -- a copy of param
  create file A/config.yaml              -- base include file
  create file A/svc_test.yaml            -- defines the service and signs users
  create file A/user_A_svc_test.yaml     -- defines the user
  create file A/user_B_svc_test.yaml     -- defines the user
  create file A/user_C_svc_test.yaml     -- defines the user
  create dir  B                          -- exported configure directory
  create file B/.salt                    -- a copy of salt
  create file B/.pass                    -- generated a new password
  create file B/param.yaml               -- a copy of param
  create file B/config.yaml              -- base include file
  create file B/svc_test.yaml            -- defines the service and signs users
  create file B/user_A_svc_test.yaml     -- defines the user
  create file B/user_B_svc_test.yaml     -- defines the user
  create file B/user_C_svc_test.yaml     -- defines the user
  create dir  C                          -- exported configure directory
  create file C/.salt                    -- a copy of salt
  create file C/.pass                    -- generated a new password
  create file C/param.yaml               -- a copy of param
  create file C/config.yaml              -- base include file
  create file C/svc_test.yaml            -- defines the service and signs users
  create file C/user_A_svc_test.yaml     -- defines the user
  create file C/user_B_svc_test.yaml     -- defines the user
  create file C/user_C_svc_test.yaml     -- defines the user
  OK? y
  done
  ```

Copy the A config to the A node/config, the B config directory to the B
node/config, etc.  The `.pass` file is unique for each peer so that it can be
removed after running the server, rendering the configured keys unreadable
until the `.pass` file is restored or the peer's config is regenerated from the
master config.

The copy of the master config includes a copy of the `param.yaml`, as that
can contain global configuration, but doesn't copy any local configuration
such as startup and network configuration.

The master config will also work, so just copying it to the peers will allow
them to run if this type of security is unnecessary.

