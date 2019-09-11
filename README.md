# SSSD OpenShift provider

This repository contains a howto and the required artifacts to use SSSD
for SSH access to worker nodes in an OpenShift cluster.

## Motivation

OpenShift already provides a handy `oc debug node/` command to spawn a pod
that mounts the host filesystem in a container's `/host` directory and lets
the user `chroot` to the directory. This is quite user-friendly and simple
to use, but goes against requirements that certain regulated environments have.

In those environments, using root directly is frowned upon, because using
the single root account for all administrators leaves no usable audit
trail behind. Instead, each user should use their own account and elevate
privileges using sudo so that the audit logs can be used to see which user
performed which administrative action on the host.

There are also other related requirements such as terminating idle sessions
that ssh configuration options might help solve nicely, but the root
auditing is the main one.

It should be noted right away that the purpose of this ssh-based approach is
not to displace `oc debug node/` for the general case, but rather provide
an alternative for deployments where `oc debug node/` cannot be used due to
regulatory issues.

At the moment, this project is in a Proof-Of-Concept stage. The code is not
the nicest, the steps to set up the environment are somewhat manual and the
SSSD provider does not work with SELinux in enforcing mode. The purpose at
the moment is to show what could be possible and gather feedback.

## User experience

The OpenShift worker nodes are typically not reachable from outside the
cluster. Therefore to reach the cluster, the administrator should set
up a bastion host. For demonstration purposes, we can also just `oc debug`
into another worker node, pretend it's a bastion and ssh to the target
worker node.

On a high level, the flow works like this: the user is authenticated with
their OAuth token which can be displayed with `oc whoami -t`, the token
is then used as a password. Access control can be restricted to certain
OpenShift groups. After login, the user is added into a group that permits
them to call `sudo`. The workflow is described in more detail later in
the document.

## Setting up the environment

This section describes the detailed steps to set up SSSD for ssh access.
You'll need an OpenShift cluster up and running and you need to have
administrative privileges to follow the steps.

### Set up an Identity Provider
SSSD will decide whether the user should be permitted to log into the
host and given administrative rights based on membership in a group.
The simplest way to set up some users and groups is to use the
[HTPassword](https://docs.okd.io/latest/install_config/configuring_authentication.html#HTPasswdPasswordIdentityProvider)
identity provider and a custom group, but the setup should work equally
well with other Identity Providers.

For the demonstration, we'll add two users - `allowed_user` and
`denied_user`. Then, `allowed_user` would be added to a group called
`cluster-admins` which would be later referenced from `sssd.conf`.
On the other hand, `denied_user` would not be a member of this group,
so we'll use them for a negative test. The password for both users
would be `Secret123`.

First, let's add the users:
```
$ htpasswd -c -B -b ./sshcluster-htpass allowed_user Secret123
$ htpasswd -B -b ./sshcluster-htpass denied_user Secret123
```

Create a secret that contains the htpasswd file contents:
```
$ oc create secret generic htpass-secret --from-file=htpasswd=./sshcluster-htpass -n openshift-config
```

Next, create a Custom Resource that references the secret holding
our htpasswd database:
```yaml
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: ssh_demo_provider
    mappingMethod: claim
    type: HTPasswd
    htpasswd:
      fileData:
        name: htpass-secret
```

Save this content to a file, e.g. `httpass-cr.yaml` and apply it:
```
$ oc apply -f htpass-cr.yaml
```
As a pre-flight check, it might be a good idea to test that you can
actually authenticate as both the users:
```
$ oc login -u allowed_user
$ oc login -u denied_user
```

Finally, we need to create a group and add the `allowed_user` user to it:
```
$ oc adm groups new cluster-admins allowed_user
```
And verify the group membership:
```
$ oc get groups
NAME             USERS
cluster-admins   allowed_user
```

### Configure the CoreOS hosts
At the moment, the CoreOS hosts lack certain configuration options that
we need in order to enable either ssh logins or SSSD authentication. We'll
configure each of the steps separately as it gives better visibility to
what the change entails.

The configuration files used can be found in the `configs` directory in
this repository. Note that some configuration files, notably `sssd.conf`
must be changed to match your environment at the moment. This is something
that might be changed if this work moves beyond a POC stage.

#### Enable `ChallengeResponseAuthentication` in the SSH daemon configuration
The latest OpenShift version set the `ChallengeResponseAuthentication`
option to `no` by default in `/etc/ssh/sshd_config`. Because we want the
users to provide their OAuth token as the password which would then be
evaluated by SSSD through the PAM stack, we need to switch this option to
`on`.

Apply the `MachineConfig` object with:
```
$ oc create -f mc-yamls/sshd_config.yaml
```
The original file is `configs/sshd_config`. No tuning to a particular
environment should be necessary.

#### Enable `pam_sss` in the `password-auth` PAM service
SSHD would authenticate the user through the PAM stack, in particular
the `pam_sss.so` module. By default, this module is not present in the
PAM stack on CoreOS hosts. We'll just replace the `password-auth` PAM service
with the one a RHEL-8 machine would use for the sake of simplicity, but
we could as well craft a more minimal PAM configuration in the future.

Apply the `MachineConfig` object with:
```
$ oc create -f mc-yamls/enable-pam_sss.yaml
```
The original file is `configs/etc_pam.d_password_auth`. No tuning to a
particular environment should be necessary.

#### Allow the `ocp-sudoers` group to call `sudo` without a password
The `sssd.conf` file we'll use later on would add each authenticated user
to a group called `ocp-sudoers`. Because we want the authenticated users
to be able to elevate their privileges with `sudo`, we'll drop a file
to `/etc/sudoers.d/ocp-sudoers-nopasswd` that allows members of that
particular group to `sudo` without a password.

Apply the `MachineConfig` object with:
```
$ oc create -f mc-yamls/ocp-sudoers-nopasswd.yaml
```
The original file is `configs/ocp-sudoers-nopasswd`. No tuning to a
particular environment should be necessary.

#### Enable the `sssd` service to start on boot
The `sssd` service must be enabled so that the `pam_sss.so` module
can talk to the `sssd` deamon for authentication and the `nss_sss`
NSS module can resolve the user identities.

Apply the `MachineConfig` object with:
```
$ oc create -f mc-yamls/enable-sss-service.yaml
```

#### Add a `sssd.conf` configuration file
The `sssd` configuration file template that can be found at
`configs/sssd_conf` must be changed to match your environment. This
is something that should be changed if we move this project our of the
POC stage, but for now, manual change is required.

Edit the file `configs/sssd_conf` and change the value of the
`ocp_api_server_url` so that it contains the URL of your API server.
Because the MachineConfig objects in the YAML file need to be URL-encoded,
run a snippet like this:
```
cat configs/sssd_conf | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(''.join(sys.stdin.readlines())))" > sssd_conf.urlencoded
```

Then edit the YAML file with the `MachineConfig` definition and place the
contents of the `sssd_conf.urlencoded` file after the `source: data:,` line
in the `mc-yamls/sssd_conf.yaml` file.

Apply the `MachineConfig` object with:
```
$ oc create -f mc-yamls/sssd_conf.yaml
```

Now we are ready with configuring the CoreOS hosts. The last thing to do
is to actually install the required SSSD packages on a host we will
be testing the authentication to.

### Replace the default SSSD packages on the CoreOS host(s)
The CoreOS hosts already ship several SSSD packages. We need to
install a newer version that includes some needed fixes and install the
`sssd-openshift` package that actually includes the OpenShift provider
for SSSD.

For installing additional packages, the `rpm-ostree` utility has a `install`
command, but because SSSD is a base package in the CoreOS host, we need
to first replace the packages alrady present on the CoreOS host and then
install the `sssd-openshift` package. What makes the steps a little more
awkward is that at the moment it is [not possible](https://github.com/projectatomic/rpm-ostree/issues/1265)
to override base packages from a repo. The packages with the overrides
must be fetched to the target host and the `rpm-ostree` invocation must
include paths to local files.

Of course, this step would not have been necessary if the required packages
were installed on the CoreOS host in the first place.

Let's log in to one of the nodes and `chroot` to the filesystem:
```
$ oc debug node/WORKER_NODE
Starting pod/WORKER_NODE-debug
To use host binaries, run `chroot /host`
If you don't see a command prompt, try pressing enter.
sh-4.2# chroot /host
```

We can grab the packages from a tarball in this repo:
```
sh-4.2# cd tmp
sh-4.2# curl -Ok https://github.com/jhrozek/sssd-openshift/blob/master/rpms/sssd-openshift.tar.bz2
sh-4.2# tar xfj sssd-openshift.tar.bz2
sh-4.2# cd sssd-openshift
```

And overlay the base packages on the host:
```
sh-4.2# rpm-ostree override replace ./sssd-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-ad-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-client-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-common-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-common-pac-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-ipa-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-krb5-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-krb5-common-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-ldap-2.0.0-43.el8.3.3.x86_64.rpm \
        ./sssd-proxy-2.0.0-43.el8.3.3.x86_64.rpm \
        ./libipa_hbac-2.0.0-43.el8.3.3.x86_64.rpm \
        ./libsss_idmap-2.0.0-43.el8.3.3.x86_64.rpm \
        ./python3-sssdconfig-2.0.0-43.el8.3.3.noarch.rpm
```
You'll need to reboot the node to apply the new tree:
```
sh-4.2# systemctl reboot
```

When the node comes up, you can finally install the `sssd-openshift` package:
```
sh-4.2# rpm-ostree install ./sssd-openshift-2.0.0-43.el8.3.2.x86_64.rpm
```
And reboot again:
```
sh-4.2# systemctl reboot
```

After the node boots up again, you should see the SSSD service running and serving the `ocp` domain:
```
sh-4.2# systemctl status sssd
● sssd.service - System Security Services Daemon
   Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
   Active: active (running) since Tue 2019-09-10 11:02:21 UTC; 2min 45s ago
 Main PID: 1001 (sssd)
    Tasks: 5 (limit: 26213)
   Memory: 39.6M
      CPU: 263ms
   CGroup: /system.slice/sssd.service
           ├─1001 /usr/sbin/sssd -i --logger=files
           ├─1031 /usr/libexec/sssd/sssd_be --domain implicit_files --uid 0 --gid 0 --logger=files
           ├─1032 /usr/libexec/sssd/sssd_be --domain ocp --uid 0 --gid 0 --logger=files
           ├─1040 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
           └─1041 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
```

### Temporarily set SELinux to Permissive mode
SSSD's OpenShift provider uses `libcurl` to talk to the OpenShift API
server's REST API. Currently this is not permitted by the shipped SELinux
policy, so for the purpose of this demo, we'll switch SELinux to Permissive
mode. This is of course something that absolutely needs to be changed for
any production use of this feature. Run `oc debug node/` to access the worker
node and run:
```
sh-4.2# setenforce 0
```

## Test the ssh access
With all the manual steps done and the worker node configured and running the
latest SSSD, it's time to test things out! We'll use two worker nodes for the
test, but as said earlier, in real world, we would have used a bastion host
instead of the "from" node.

Let's start with the `allowed_user` to check the positive case. Log in as the
user and obtain their OAuth token:
```
$ oc login -u allowed_user
$ oc whoami -t
8QDdFmRiKQi-DI8EQ-3ROfJGnf0zsj_ewoS58XmWIDI
```

Now run `oc debug node/FROM_NODE` where `FROM_NODE` is the address of another
OpenShift worker node, different than the one you installed SSSD to and chroot
to the `/host` directory:
```
$ oc debug node/FROM_NODE
Starting pod/FROM_NODE-debug
To use host binaries, run `chroot /host`
If you don't see a command prompt, try pressing enter.
sh-4.2# chroot /host
```

Now we can finally ssh to the node where we installed SSSD at. When asked for a
password, use the token you obtained with the `oc login -t` command:
```
sh-4.2# ssh allowed_user@TO_NODE
Password:
Red Hat Enterprise Linux CoreOS 42.80.20190910.0
WARNING: Direct SSH access to machines is not recommended.

---
Last login: Tue Sep 10 14:36:16 2019 from 10.0.150.128
[allowed_user@TO_NODE /]$
```

Great, we're in. Running `id` should list the user as a member of the
`ocp-sudoers` group:
```
[allowed_user@TO_NODE /]$ id
uid=10002(allowed_user) gid=10002(allowed_user) groups=10002(allowed_user),10000(ocp-sudoers) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

And this user should be allowed to call `sudo`:
```
[allowed_user@TO_NODE /]$ sudo head -n1 /etc/shadow
root:!locked::0:99999:7:::
```

As described above, only certain users are allowed access to the node,
depending on their group membership as configured in the `sssd.conf`'s
`ocp_allowed_groups` option. So let's try a negative test with the
`denied_user`, again using their token to log in. From the same worker
node:

```
ssh denied_user@TO_NODE
Password:
Connection closed by 10.0.140.158 port 22
```

To explain further why this user was not allowed to log in, we can check out
the audit log in the node running SSSD. We should see something like this:
```
type=USER_AUTH msg=audit(1568130397.640:236): pid=79779 uid=0 auid=4294967295
ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
msg='op=PAM:authentication
grantors=pam_succeed_if,pam_succeed_if,pam_sss acct="denied_user"
exe="/usr/sbin/sshd"
hostname=10.0.150.128 addr=10.0.150.128
terminal=ssh
res=success'
```

This line tells us the user attempted to authenticate (`type=USER_AUTH`) and
that the authentication was sucessful (`res=success`) which is expected because
we presented the correct credentials. But the next line:
```
type=USER_ACCT msg=audit(1568130397.645:237): pid=79779 uid=0 auid=4294967295
ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
msg='op=PAM:accounting grantors=?
acct="denied_user"
exe="/usr/sbin/sshd"
hostname=10.0.150.128
addr=10.0.150.128 terminal=ssh res=failed'
```
Says that the user was denided (`res=failed`) when the access control
(`type=USER_ACCT`) was attempted.

## Technical details
TBD

## Further work
TBD
