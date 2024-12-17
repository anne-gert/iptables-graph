iptables-graph
==============

This script converts iptables rules to a diagram.

It uses GraphViz for the image rendering.

If this script is called as root and without arguments, it runs iptables
to discover the rules. Otherwise, it expects it expects the input files to
contain a dump of 'iptables -L -n -v' (or equivalent). A file name may be
'-' to use stdin.

The output filename is reported on stdout.

Examples:

```bash
$ sudo iptables -L -v -n | ./iptables-graph.pl -
```

Render image with chains of filter table. Script does not run as root.

```bash
$ sudo iptables -t filter -L -v -n > iptables-filter.rules
$ sudo iptables -t nat -L -v -n > iptables-nat.rules
$ ./iptables-graph.pl iptables-filter.rules iptables-nat.rules
```

Render image with chains of filter and nat tables.

```bash
# ./iptables-graph.pl
```

Render images with chains of all (standard) tables.

