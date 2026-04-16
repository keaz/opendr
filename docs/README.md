# OpenDR Documentation

This directory contains the developer runbooks used by the OpenDR documentation
website.

## Website

- Published site: <https://keaz.github.io/opendr/>
- React site source: [`site/`](https://github.com/keaz/opendr/tree/main/site)
- [Deployment notes](./GITHUB_PAGES.md)

The website is a Vite app. Configure GitHub Pages for the `keaz/opendr`
repository to use GitHub Actions; `.github/workflows/vite-deploy.yml` builds and
deploys the site.

## Developer Runbooks

- [Developer operations guide](./DEVELOPER_GUIDE.md)
- [Configuration reference](./CONFIGURATION.md)
- [Management console](./MANAGEMENT_CONSOLE.md)
- [Troubleshooting guide](./TROUBLESHOOTING.md)
- [Backup and restore](./BACKUP_RESTORE.md)
- [Replication guide](./REPLICATION_GUIDE.md)
- [Fuzzing gate](./FUZZING.md)
- [TLS certificate rotation](./TLS_ROTATION.md)
- [LDAP referral and alias support](./LDAP_REFERRAL_ALIAS_SUPPORT.md)
- [LDAP control and extension compatibility](./LDAP_CONTROL_EXTENSION_COMPATIBILITY.md)
- [LDAP RFC compliance matrix](./LDAP_RFC_COMPLIANCE_MATRIX.md)
- [Production readiness checklist](./PRODUCTION_READINESS_CHECKLIST.md)

## Implementation References

- [Architecture overview](./architecture-overview.md)
- [Class diagram](./class-diagram.md)
- [Connection FSM](./connection_fsm.md)
- [BER decoder FSM](./ber_decoder_fsm.md)
- [Auth FSM](./auth_fsm.md)
- [Search FSM](./search_fsm.md)
- [Write FSM](./write_fsm.md)
- [Compare FSM](./compare_fsm.md)
- [Extended operation FSM](./extended_op_fsm.md)
- [Backend transaction FSM](./backend_txn_fsm.md)
- [Replication consumer FSM](./replication_consumer_fsm.md)
- [Schema integration](./schema_integration.md)
- [Performance comparison](./PERFORMANCE_COMPARISON.md)

Start with the developer operations guide when setting up or troubleshooting a
server. Use the implementation references when changing runtime code.
