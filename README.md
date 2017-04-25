Container Security Best Practices
------------------------------

Last Updated 2017-04-25

## Policy Security

Security policy might be more important than actual system configuration in terms of configuring Docker securely.

**Anyone with permissions to run Docker commands effectively has root access to the host system!**

Consider [Dan Walsh's](https://twitter.com/rhatdan) excellent example:

    # Don't run this!
    sudo docker run -v /:/host_root:rw --privileged -it centos:latest rm -rf /host_root

Therefore, rule numero uno:

_Only trusted users get access to run docker commands_

---

## Policy Security cont.

_Do not run untrusted container images_

A research group scanned the Docker Hub's Official images in 2015 and found a staggering 30% were vulnerabile to critical security vulnerabilities.  These are teh _officially supported_ images from Docker Hub.

You can reasonably trust the official base images for the major distributions, with a caveat: they are frequently intentionally not patched after each release, to maintain the same patchlevel as ISO images released on a schedule.

The only way to truly maintain a secure image is to build your own:  on a schedule - or with a CI software like Jenkins - pull the latest base image from upstream and apply patches.  Use the resulting image as a base for the rest of your Docker image builds.

Alternatively, and with some caution, you can repackage official application images, such as RabbitMQ, Jenkins, etc.  Ideally, find the Github repo for the project, and build your own image based on the Dockerfile there, making sure to patch.  A caveat here is that the software application itself is unlikely to be installed via a package manager of any kind, so you'll need to check the versions and update them accordingly.

In addition to the software patches themselves, you should also audit the software configuration.  A fully patched Apache server is useless if some bit of virtual host configuration in the default image is insecure.  _Ex. TLS protocols and Ciper Suites_

At this point we are leading away from policy and into System Security...

## System Security 

_Consider Blocking Untrusted Registries_

Red Hat distributions patch the Docker software to allow some extra configuration, one of which is the ability to specify untrusted registries to block.  Uncommenting "BLOCK_REGISTRY=" in /etc/sysconfig/docker will allow you to disable access to registries listed there.

If you are repackaging base images and maintaining a local registry, consider blocking all but your own registry for all but the hosts building those images.  This will prevent users from pulling images you may not trust.  Non-Red Hat bases systems can accomplish the same thing with DNS black holes, firewalls, etc.

_Always enable SELinux_

Docker security is effectively enhanced by keeping SELinux enabled and applying sane policies around Docker.  Once again, Dan Walsh is an excellent resource for [how this works](http://rhelblog.redhat.com/2017/01/13/selinux-mitigates-container-vulnerability/).

_Drop any system capabilities you don't need_

By default, Docker runs with the following system capabilities:

* SETPCAP	
  Modify process capabilities.
* MKNOD
  Create special files using mknod(2).
* AUDIT_WRITE
  Write records to kernel auditing log.
* CHOWN
  Make arbitrary changes to file UIDs and GIDs (see chown(2)).
* NET_RAW
  Use RAW and PACKET sockets.
* DAC_OVERRIDE
  Bypass file read, write, and execute permission checks.
* FOWNER
  Bypass permission checks on operations that normally require the file system UID of the process to match the UID of the file.
* FSETID
  Don’t clear set-user-ID and set-group-ID permission bits when a file is modified.
* KILL
  Bypass permission checks for sending signals.
* SETGID
  Make arbitrary manipulations of process GIDs and supplementary GID list.
* SETUID
  Make arbitrary manipulations of process UIDs.
* NET_BIND_SERVICE
  Bind a socket to internet domain privileged ports (port numbers less than 1024).
* SYS_CHROOT
  Use chroot(2), change root directory.
* SETFCAP
  Set file capabilities.

If your container doesn't require some of these to run, drop the capabilities with the `--cap-drop=` argument.  For example, if your container doesn't need to open any ports, consider using `--cap-drop=NET_BIND_SERVICE` with your `docker run` command.

_Protect the Docker HTTP Socket_

By default, Docker will bind to a local Unix socket.  It can, however, use an HTTP socket for communication.  **Never expose this socket to the world!**  Access to the HTTP socket is by default not protected with any authentication mechanism.

If you do turn on the HTTP Socket, make sure to [use TLS authentication](https://docs.docker.com/engine/security/https/) to protect access to the socket.  Even on top of TLS authentication, it would be a good idea to protect access to the port entirely with a host- or network-based firewall or IPS.

_Do not store secrets in environment variables_

Unfortunately, there are a large number of poorly thought out articles about Docker that use suggest using environment variables to store or pass secrets into a contianer.  Just as you would on a regular server, protect credentials and secrets as thoroughly as you can.  Containers are not so secure that you should assume these environment variables are not readable by anyone.

_Destroy Containers Regularly_

One nice benefit of image-based systems like containers is the ability to "reset" an application to the known-good state simply by replacing it with a fresh copy.  Containers are by nature ephemeral, and you should take advantage of this fact by destroying them regularly.  Aside from persistent data, this ensures your container is identical to what you expect from it's parent image, and any potential problems or compromised access is destroyed with the container.

However, this leads to the next point...

_Log EVERYTHING_

When you destroy a container, all record of any potential compromise, any system issue...really anything...is lost for good.  More than any other system, make sure the daemon, container, services inside the container, host logs, access logs, etc. are all logged to a central location off of the system.  Docker has a number of logging provider plugins available for logging daemon and container logs, but make sure to grab logs from services inside the containers as well.

_Run contianers with an unprivileged user inside_

Wherever possible, switch the user inside of the container to an unprivileged user.  This may not be possible for services that expect to start up as root, even if they then subsequently drop permissions, but if it's supported, run as a non-root user inside the contianers.

_Run containers with an unprivileged user outside_

Docker, and Linux containers in general, support _user namespaces_.  The Linux kernel added support in version 3.8, and Docker added support for user namespaces in version 1.10.

"Think of these as nested data structures within a new namespace. In this new namespace, there is a virtual set of users and groups. These users and groups, beginning with uid/gid 0 are mapped to a non-trusted (not root) uid/gid outside the namespace." [What’s Next for Containers? User Namespaces](http://rhelblog.redhat.com/2015/07/07/whats-next-for-containers-user-namespaces/)

Namespaces in Docker prevent users from running privileged contianers, accessing files mounted inside of containers using the root users from inside the container, etc.

Even better than namespaces are completely unprivileged containers, such as those used by the [Singularity container project](http://singularity.lbl.gov/).  

## License

The information contained in this repository is licensed: 

*Creative Commons CC0 1.0 Universal*

[More Info](LICENSE.md)
