#!/usr/bin/env python
from StringIO import StringIO
import argparse
import sys
import yaml
import os

from fabric.api import sudo, settings, run, hide, put, shell_env, local, cd, get
from fabric.contrib.files import exists, contains, append, sed
from fabric.colors import green, red, yellow

from workarounds import fix_aio as fix
from utils import collect_logs, dump, all_servers, quit_if_fail, warn_if_fail, update_time, resolve_names, CONFIG_PATH, \
    LOGS_COPY, change_ip_to

__author__ = 'sshnaidm'

DOMAIN_NAME = "domain.name"
APPLY_LIMIT = 3
# override logs dirs if you need
LOGS_COPY = {
    "/etc": "etc_configs",
    "/var/log": "all_logs",
    "/etc/puppet": "puppet_configs",
}


def install_openstack(settings_dict, envs=None, verbose=None, prepare=False, force=False, proxy=None, config=None):
    """
    Install OS with COI with script provided by Chris on any host(s)

    :param settings_dict: settings dictionary for Fabric
    :param envs: environment variables to inject when executing job
    :param verbose: if to hide all output or print everything
    :param url_script: URl of Cisco installer script from Chris
    :param force: Use if you don't connect via interface you gonna bridge later
    :return: always true
    """
    envs = envs or {}
    verbose = verbose or []
    if settings_dict['user'] != 'root':
        use_sudo_flag = True
        run_func = sudo
    else:
        use_sudo_flag = False
        run_func = run

    with settings(**settings_dict), hide(*verbose), shell_env(**envs):
        with cd("~/"):
            if proxy:
                warn_if_fail(put(StringIO('Acquire::http::proxy "http://proxy.esl.cisco.com:8080/";'),
                                 "/etc/apt/apt.conf.d/00proxy",
                                 use_sudo=use_sudo_flag))
                warn_if_fail(put(StringIO('Acquire::http::Pipeline-Depth "0";'),
                                 "/etc/apt/apt.conf.d/00no_pipelining",
                                 use_sudo=use_sudo_flag))
            update_time(run_func)
            warn_if_fail(run_func("apt-get update"))
            warn_if_fail(run_func('DEBIAN_FRONTEND=noninteractive apt-get -y '
                                  '-o Dpkg::Options::="--force-confdef" -o '
                                  'Dpkg::Options::="--force-confold" dist-upgrade'))
            warn_if_fail(run_func("apt-get install -y git"))
            warn_if_fail(run("git config --global user.email 'test.node@example.com';"
                             "git config --global user.name 'Test Node'"))
            warn_if_fail(sed("/etc/hosts", "127.0.1.1.*",
                             "127.0.1.1 all-in-one all-in-one.domain.name", use_sudo=use_sudo_flag))
            warn_if_fail(put(StringIO("all-in-one"), "/etc/hostname", use_sudo=use_sudo_flag))
            warn_if_fail(run_func("hostname all-in-one"))
            if not force and prepare:
                return True
            elif not force and not prepare:
                warn_if_fail(run("git clone https://github.com/openstack-dev/devstack.git"))
                with cd("devstack"):
                    warn_if_fail(run("./stack.sh"))
            elif force:
                shell_envs = ";".join(["export " + k + "=" + v for k, v in envs.iteritems()]) or ""
                sudo_mode = "sudo " if use_sudo_flag else ''
                if not settings_dict['gateway']:
                    local("{shell_envs}; ssh -t -t -i {id_rsa} {user}@{host} \
                     'git clone https://github.com/openstack-dev/devstack.git; cd devstack; ./stack.sh'".format(
                        shell_envs=shell_envs,
                        id_rsa=settings_dict['key_filename'],
                        user=settings_dict['user'],
                        host=settings_dict['host_string']))
                    local("scp -i {id_rsa} {user}@{host}:~/openrc ./openrc".format(
                        id_rsa=settings_dict['key_filename'],
                        user=settings_dict['user'],
                        host=settings_dict['host_string']))
                else:
                    local('ssh -t -t -i {id_rsa} {user}@{gateway} \
                     "{shell_envs}; ssh -t -t -i {id_rsa} {user}@{host} \
                     \'{sudo_mode}git clone https://github.com/openstack-dev/devstack.git;\
                      cd devstack; ./stack.sh\'"'.format(
                        shell_envs=shell_envs,
                        id_rsa=settings_dict['key_filename'],
                        user=settings_dict['user'],
                        host=settings_dict['host_string'],
                        gateway=settings_dict['gateway'],
                        sudo_mode=sudo_mode))
                    local('scp -Cp -o "ProxyCommand ssh {user}@{gateway} '
                          'nc {host} 22" {user}@{host}:~/openrc ./openrc'.format(
                        user=settings_dict['user'],
                        host=settings_dict['host_string'],
                        gateway=settings_dict['gateway'],
                    ))
        if exists('~/openrc'):
            get('~/openrc', "./openrc")
        else:
            print (red("No openrc file, something went wrong! :("))
    print (green("Finished!"))
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', action='store', dest='user',
                        help='User to run the script with')
    parser.add_argument('-p', action='store', dest='password',
                        help='Password for user and sudo')
    parser.add_argument('-a', action='append', dest='hosts', default=[],
                        help='List of hosts for action')
    parser.add_argument('-g', action='store', dest='gateway', default=None,
                        help='Gateway to connect to host')
    parser.add_argument('-q', action='store_true', default=False, dest='quiet',
                        help='Make all silently')
    parser.add_argument('-x', action='store', default="eth1", dest='external_interface',
                        help='External interface: eth0, eth1... default=eth1')
    parser.add_argument('-d', action='store', default="eth0", dest='default_interface',
                        help='Default interface: eth0, eth1... default=eth0')
    parser.add_argument('-k', action='store', dest='ssh_key_file', default=None,
                        help='SSH key file, default is from repo')
    parser.add_argument('-z', action='store_true', dest='prepare_mode', default=False,
                        help='Only prepare, don`t run the main script')
    parser.add_argument('-f', action='store_true', dest='force', default=False,
                        help='Force SSH client run. Use it if dont work')
    parser.add_argument('-j', action='store_true', dest='proxy', default=False,
                        help='Use cisco proxy if installing from Cisco local network')
    parser.add_argument('-c', action='store', dest='config_file', default=None,
                        help='Configuration file, default is None')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    opts = parser.parse_args()
    if opts.quiet:
        verb_mode = ['output', 'running', 'warnings']
    else:
        verb_mode = []
    path2ssh = os.path.join(os.path.dirname(__file__), "..", "libvirt-scripts", "id_rsa")
    ssh_key_file = opts.ssh_key_file if opts.ssh_key_file else path2ssh
    if not opts.config_file:
        envs_aio = {"default_interface": opts.default_interface,
                    "external_interface": opts.default_interface}
        hosts = opts.hosts
        user = opts.user
        password = opts.password
        config = None
    else:
        try:
            with open(opts.config_file) as f:
                config = yaml.load(f)
        except IOError as e:
            print >> sys.stderr, "Not found file {file}: {exc}".format(file=opts.config_file, exc=e)
            sys.exit(1)
        aio = config['servers']['aio-server']
        hosts = [aio["ip"]]
        user = aio["user"]
        password = aio["password"]
        envs_aio = {"default_interface": aio["default_interface"],
                    "external_interface": aio["external_interface"]}

    job_settings = {"host_string": "",
                    "user": user,
                    "password": password,
                    "warn_only": True,
                    "key_filename": ssh_key_file,
                    "abort_on_prompts": True,
                    "gateway": opts.gateway}
    for host in hosts:
        job_settings['host_string'] = host
        print >> sys.stderr, job_settings
        print >> sys.stderr, envs_aio
        res = install_openstack(job_settings,
                                verbose=verb_mode,
                                envs=envs_aio,
                                prepare=opts.prepare_mode,
                                force=opts.force,
                                proxy=opts.proxy)
        if res:
            print "Job with host {host} finished successfully!".format(host=host)


if __name__ == "__main__":
    main()
