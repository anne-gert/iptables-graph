#!/usr/bin/perl

# This script converts iptables rules to a diagram.
# It uses GraphViz for the image rendering.
#
# If this script is called as root and without arguments, it runs iptables
# to discover the rules. Otherwise, it expects it expects the input files to
# contain a dump of 'iptables -L -n -v' (or equivalent). A file name may be
# '-' to use stdin.
# The output filename is reported on stdout.
#
# Examples:
#
# $ sudo iptables -L -v -n | ./iptables-graph.pl -
#
# Render image with chains of filter table. Script does not run as root.
#
# $ sudo iptables -t filter -L -v -n > iptables-filter.rules
# $ sudo iptables -t nat -L -v -n > iptables-nat.rules
# $ ./iptables-graph.pl iptables-filter.rules iptables-nat.rules
#
# Render image with chains of filter and nat tables.
#
# # ./iptables-graph.pl
#
# Render images with chains of all (standard) tables.

use strict;
use File::Temp qw/tempfile/;

my $input_iptables = 0;
my $input_files = 0;
if (@ARGV > 0)
{
	# There are arguments, use those
	$input_files = [ @ARGV ];
}
elsif ($> == 0)
{
	# There are no arguments, but called as root, so call iptables
	# ourselves.
	$input_iptables = 1;
}
else
{
	# No suitable input.
	die "This program should be run as root or input files should be provided on the commandline ('-' for stdin).\n";
}

sub find_command
{
	my ($generic_name, @options) = @_;

	my $found;
	foreach (@options)
	{
		if (-x $_)
		{
			$found = $_;
			last;
		}
	}
	die "Could not find '$generic_name' command\n" unless defined $found;
	print "$generic_name: Use '$found'\n";
	return $found;
}

# Find the commands to use
my $iptables_cmd;
if ($input_iptables)
{
	$iptables_cmd = find_command 'iptables', '/usr/sbin/iptables', '/sbin/iptables';
}
my $dot_cmd = find_command 'dot', '/usr/bin/dot', '/bin/dot';

# Read defined protocol numbers
my %protocols;
my $protocols_fname = '/etc/protocols';
if (-r $protocols_fname)
{
	if (open my $fh, "<", $protocols_fname)
	{
		foreach (<$fh>)
		{
			if (/^\s*(\S+)\s+(\d+)/)
			{
				# Read valid protocol number definition
				my ($name, $number) = ($1, 1*$2);
				$protocols{$number} = $name;
			}
		}
	}
}
#use Data::Dumper; print "\%protocols: ", Dumper \%protocols;

my $genID = 0;  # node ID generator (singleton)

sub render_graph
{
	my ($chains) = @_;

	# Parse through rules
	my %policy;  # chain -> policy
	my %rules;  # chain -> array of rule objects
	my %start;  # chain -> nodeID
	my $currChain;
	foreach my $rule (@$chains)
	{
		if ($rule =~ /^\s*$/)
		{
			# Empty line -> skip
		}
		elsif ($rule =~ /^\s*#/)
		{
			# Commented line -> skip
		}
		elsif ($rule =~ /^\s*Chain\s+(\S+)\s*(.*)/i)
		{
			# This line starts the rules for a new chain
			($currChain, my $tail) = ($1, $2);
			if ($tail =~ /policy (ACCEPT|REJECT|DROP)/i)
			{
				$policy{$currChain} = uc $1;
			}
		}
		elsif ($rule =~ /\btarget\s+prot/i)
		{
			# This line contains table headings
		}
		elsif ($rule =~ m{^
			\s*(\S+)\s+(\S+)            # number of packets / bytes
			\s+(\S+)\s+(\S+)\s+(\S+)    # target / protocol / options
			\s+(\S+)\s+(\S+)            # input / output
			\s+(\S+)\s+(\S+)            # source / destination
			(?:\s+(.*?))?\s*            # optional arguments
			$}x)
		{
			# This line is a rule
			my ($num_packets, $num_bytes,
				$target, $protocol, $options,
				$input, $output,
				$source, $destination,
				$arguments) =
				($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

			my $nodeID = "N" . ++$genID;
			my %rule = (
				#chain => $currChain,
				target => $target,
				id => $nodeID,
			);
			if ($protocol =~ /^0*$/)
			{
				# No protocol
			}
			elsif ($protocol =~ /^\d+$/ && defined $protocols{1*$protocol})
			{
				$rule{protocol} = $protocols{1*$protocol};
			}
			else
			{
				$rule{protocol} = $protocol;
			}
			$rule{options} = $options unless $options =~ /^-*$/;
			$rule{input} = $input unless $input eq "*";
			$rule{output} = $output unless $output eq "*";
			$rule{source} = $source unless $source eq "0.0.0.0/0";
			$rule{destination} = $destination unless $destination eq "0.0.0.0/0";
			$rule{arguments} = $arguments unless $arguments eq "";

			push @{$rules{$currChain} ||= []}, \%rule;  # add the rule

			$start{$currChain} ||= "S" . $genID;  # set the start if this is the first
		}
		else
		{
			die "Unknown line in output from iptables: $rule";
		}
	}
	#use Data::Dumper; print "\%policy: ", Dumper \%policy;
	#use Data::Dumper; print "\%rules: ", Dumper \%rules;

	# Render the chains to GraphViz DOT language statements
	my $ColorStart = "#ccccff";  # chain start
	my $ColorBlock = "#ffcccc";  # block a packet
	my $ColorAllow = "#ccffcc";  # allow a packet
	my $ColorModify = "#ffffcc";  # modify a packet
	my $ColorLog = "#999999";  # non-changing processing, like LOG
	my $ColorJump = "#ccffff";  # jump/return to other chain
	my $ColorUnknown = "#eeeeee";  # not any of the above
	my %KnownTarget = (
		ACCEPT => {
			color => $ColorAllow,
			terminating => 1,
		},
		DNAT => {  # Destination Network Address Translation
			color => $ColorModify,
			terminating => 0,
		},
		SNAT => {  # Source Network Address Translation
			color => $ColorModify,
			terminating => 0,
		},
		MASQUERADE => {  # specialized form of SNAT
			color => $ColorModify,
			terminating => 0,
		},
		REDIRECT => {  # specialized form of DNAT
			color => $ColorModify,
			terminating => 0,
		},
		DROP => {
			color => $ColorBlock,
			terminating => 1,
		},
		REJECT => {
			color => $ColorBlock,
			terminating => 1,
		},
		LOG => {
			color => $ColorLog,
			terminating => 0,
			fold => "optional",
		},
		RETURN => {
			color => $ColorJump,
			terminating => 0,
		}
	);
	my (@nodes, @edges);
	foreach my $chain (sort keys %rules)
	{
		my $rules = $rules{$chain};
		if (@$rules > 0)
		{
			# Preprocess rules
			my @items = ();  # node data objects
			foreach my $rule (@$rules)
			{
				my $nodeID = $$rule{id};
				my $target = $$rule{target};

				# Selector
				my @selector;
				my $input = $$rule{input};
				my $output = $$rule{output};
				my $source = $$rule{source};
				my $destination = $$rule{destination};
				my $protocol = $$rule{protocol};
				my $arguments = $$rule{arguments};
				push @selector, "i=$input" if $input;
				push @selector, "o=$output" if $output;
				push @selector, "s=$source" if $source;
				push @selector, "d=$destination" if $destination;
				my $log_prefix;
				if ($arguments =~ /^\s*(?:(.*?)\s+)?LOG\s.*?prefix\s*"(.*)"/)
				{
					# This is a LOG rule
					($arguments, $log_prefix) = ($1, $2);
				}
				if ($protocol && $protocol ne "all" && $arguments !~ /\b\Q$protocol\E\b/i)
				{
					# Protocol is set and it is not included in the arguments
					push @selector, "p=$protocol";
				}
				if ($arguments)
				{
					push @selector, $arguments;  # may include protocol
				}

				# Extra arguments
				my @extra;
				if ($log_prefix)
				{
					push @extra, "prefix=\"$log_prefix\"";
				}

				# Add data as item
				push @items, {
					id       => $nodeID,
					target   => $target,
					selector => \@selector,
					extra    => \@extra
				};
			}

			# Fold foldable nodes
			for (my $i = 1; $i < @items; ++$i)
			{
				my $prev = $items[$i-1];
				my $prevTarget = $$prev{target};
				my $prevSelector = join " ", @{$$prev{selector}};
				my $prevDef = $KnownTarget{$prevTarget};

				my $item = $items[$i];
				my $target = $$item{target};
				my $selector = join " ", @{$$item{selector}};
				my $itemDef = $KnownTarget{$target};

				# If the previous is opional and the selectors are te same
				if ($prevDef && $$prevDef{fold} eq "optional" && $prevSelector eq $selector)
				{
					push @{$$item{extra}}, @{$$prev{extra}};
					$$item{extra_targets} = [ $prevTarget ];
					$items[$i-1] = undef;
				}

				# If both nodes are non-special and have the same target
				if (!$prevDef && !$itemDef && $prevTarget eq $target)
				{
					# Prepend selector
					if (@{$$prev{selector}})
					{
						unshift @{$$item{selector}}, "OR";
						unshift @{$$item{selector}}, @{$$prev{selector}};
					}
					# Prepend extra
					if (@{$$prev{extra}})
					{
						unshift @{$$item{extra}}, "OR";
						unshift @{$$item{extra}}, @{$$prev{extra}};
					}
					$items[$i-1] = undef;
				}
			}
			@items = grep $_, @items;  # filter out deleted ones

			# Render first pseudo-node with chain name
			my $startID = $start{$chain};
			push @nodes, qq($startID [fillcolor="$ColorStart", style=filled shape=box label="$chain"]);

			# Render items as nodes
			my $prevID = $startID;
			foreach my $item (@items)
			{
				my ($nodeID, $target, $extra_targets, $selector, $extra) =
					@$item{qw/id target extra_targets selector extra/};

				# Derive color
				my $nodeDef = $KnownTarget{$target};
				my $color;
				if ($nodeDef)
				{
					# Standard target
					$color = $$nodeDef{color};
				}
				else
				{
					# Target is other chain
					$color = $ColorJump;
					# Edge to other chain
					push @edges, qq($nodeID -> $start{$target});
				}

				# Render text
				my @targets;
				push @targets, @$extra_targets if $extra_targets;
				push @targets, $target;
				my $targets = join " + ", @targets;
				my $text = join "\n", @$selector, @$extra, $targets;
				$text =~ s/"/\\"/g;  # escape '"'

				# Render node & edge
				push @nodes, qq($nodeID [fillcolor="$color" style=filled label="$text"]);
				# Render edge to it
				push @edges, qq($prevID -> $nodeID);
				$prevID = $nodeID;
			}

			# Render the end of the chain as a pseudo-node too
			my $endID = "E" . ++$genID;
			my ($pseudoTarget, $targetType);
			if (my $policy = $policy{$chain})
			{
				# This chain has a policy
				$pseudoTarget = $policy;
				$targetType = "Policy";
			}
			else
			{
				# A chain without a policy implicitly returns
				$pseudoTarget = "RETURN";
				$targetType = "Implicit";
			}
			my $nodeDef = $KnownTarget{$pseudoTarget};
			my $color;
			if ($nodeDef)
			{
				$color = $$nodeDef{color};
			}
			else
			{
				$color = $ColorUnknown;
			}
			my $text = join "\n", $targetType, $pseudoTarget;
			# Render node
			push @nodes, qq($endID [fillcolor="$color" style=filled shape=box label="$text"]);
			# Render edge to it
			push @edges, qq($prevID -> $endID);
		}
	}

	return ( \@nodes, \@edges );
}

sub render_image
{
	my ($name, $chains) = @_;

	# Render nodes and edges
	my ($nodes, $edges) = render_graph $chains;

	next unless @$nodes || @$edges;  # skip generation unless there is actual contents

	# Render GraphViz contents
	my $output = qq(digraph "$name" {\n);
	$output .= join "", map "  $_\n", @$nodes, @$edges;
	$output .= "}\n";

	# Render to an image
	my ($out_fh, $temp_fname) = tempfile SUFFIX => ".gv", UNLINK => 1;
	#my $temp_fname = "output-$table.gv"; open my $out_fh, ">", $temp_fname or die "Cannot open '$temp_fname': $!";
	print "Using temp file '$temp_fname'\n";
	print $out_fh $output or die "Cannot write to '$temp_fname': $!";
	close $out_fh or die "Cannot close '$temp_fname': $!";

	my $out_fname = "$name.png";
	print "Render image '$out_fname'\n";
	system $dot_cmd, $temp_fname, "-Tpng", "-o$out_fname";

	#unlink $temp_fname;
}

if ($input_iptables)
{
	# Retrieve the iptables rules
	# About tables, chains and targets, see also https://www.fosslinux.com/99706/understanding-iptables-chains-and-targets-in-linux-firewall.htm
	foreach my $table (qw/filter nat mangle raw security/)
	{
		# Read the chains
		my @chains = `"$iptables_cmd" -t $table -L -n -v`;

		# Create the image
		render_image "iptables-$table", \@chains;
	}
}

if ($input_files)
{
	foreach my $fname (@$input_files)
	{
		# Read the chains
		my ($name, @chains);
		if ($fname eq "-")
		{
			$name = "iptables-chains";
			@chains = <STDIN>;
		}
		else
		{
			$name = $fname;
			$name =~ s/^.*[\/\\]//;  # remove path
			$name =~ s/\.[^.]+$//;  # remove extension
			open my $fh, "<", $fname or die "Cannot open '$fname': $!";
			@chains = <$fh> or die "Cannot read from '$fname': $!";
			close $fh;
		}

		# Create the image
		render_image $name, \@chains;
	}
}

