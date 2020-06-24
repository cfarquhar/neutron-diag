# Patch

## Prep
```
# Ensure all network agents are alive and up
openstack network agent list
```

## Apply patch to $FIRST_COMPUTE_NODE
```
cd /opt/openstack-ansible/neutron-diag
ansible-playbook apply-patches.yml --ask-vault-pass --limit $FIRST_COMPUTE_NODE
```

## Validate success on $FIRST_COMPUTE_NODE
```
ssh $FIRST_COMPUTE_NODE tail -f /var/log/neutron/neutron-linuxbridge-agent.log
# Ensure that:
#   - service is running (i.e. new logs are being generated)
#   - there are no stack traces or other errors

# Ensure all network agents are alive and up
openstack network agent list
```

## Apply patch to remaining compute nodes
```
cd /opt/openstack-ansible/neutron-diag
ansible-playbook apply-patches.yml --ask-vault-pass --limit \!$FIRST_COMPUTE_NODE
```

## Validate
```
# Ensure all network agents are alive and up
openstack network agent list
```

# Rollback / revert patching

```
ansible-playbook --ask-vault-pass restore-originals.yml
``` 
