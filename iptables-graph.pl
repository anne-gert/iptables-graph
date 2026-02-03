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

			# Beautify protocol
			if ($protocol =~ /^0*$/ || $protocol eq "all")
			{
				$protocol = undef;
			}
			elsif ($protocol =~ /^\d+$/ && defined $protocols{1*$protocol})
			{
				$protocol = $protocols{1*$protocol};
			}

			# Split arguments in limiting arguments (filter) and
			# controlling arguments (extra).
			sub match_out
			{
				my ($textref, $prefix, $options) = @_;

				my $options = "(?:" . (join "|", @$options) . ")";  # OR-ing options
				my $re = qr/(?<opt>$options(?:\s+$options)*)/;  # sequence of 1..n
				if ($prefix ne "")
				{
					$re = qr/\b$prefix\s+$re/;
				}

				my $matched = undef;
				$$textref =~ s/$re/$matched = $+{opt}; ""/e;  # take out matched
				return $matched;
			}

			# Get out the filtering options
			my @filter;
			push @filter, $protocol if $protocol;
			# Match UDP/TCP port options
			my $matched = match_out \$arguments, qr/(?:udp|tcp)/, [
				qr/(?:dpt|spt):\d+/,
				qr/(?:dpts|spts):\d+:\d+/,
				qr/flags:[\dx\/]+/,
			];
			push @filter, $matched if $matched;
			# Match MULTIPORT options
			my $matched = match_out \$arguments, "multiport", [
				qr/[ds]ports\s+[\d,]+/,
			];
			push @filter, $matched if $matched;
			# Match STATE options
			my $matched = match_out \$arguments, "", [
				qr/state\s+[A-Z,]+/,
			];
			push @filter, $matched if $matched;
			# Match ICMP options
			my $matched = match_out \$arguments, "", [
				qr/icmptype\s+\d+/,
			];
			push @filter, $matched if $matched;
			# Match match-set options
			my $matched = match_out \$arguments, "match-set", [
				qr/[\w-]+/,
			];
			push @filter, $matched if $matched;

			# Get out the extra options
			my @extra;
			# - Match LOG options
			my $matched = match_out \$arguments, "LOG", [
				qr/flags\s+\d+/,
				qr/level\s+\d+/,
				qr/prefix\s+"[^"]*"/,
			];
			push @extra, "log $1" if $matched =~ /prefix\s+("[^"]+")/;
			# Match LIMIT options
			my $matched = match_out \$arguments, "limit:", [
				qr/avg\s+\d+\/\w+/,
				qr/burst\s+\d+/,
			];
			push @extra, "rate-limited" if $matched;
			# Match REJECT options
			my $matched = match_out \$arguments, "", [
				qr/reject-with\s+\S+/,
			];
			push @extra, $1 if $matched =~ / (.+)/;
			# Match REDIRECT options
			my $matched = match_out \$arguments, "redir", [
				qr/ports\s+\d+/,
			];
			push @extra, $matched if $matched;
			# Match REDIRECT options
			my $matched = match_out \$arguments, "", [
				qr/to:\S+/,
			];
			push @extra, $matched if $matched;

			# Arguments should be empty now, print error if it isn't
			if ($arguments =~ /\S/)
			{
				print "ERROR: Unmatched arguments: '$arguments'\n";
				# Clean-up and add to @extra
				$arguments =~ s/^\s+//;
				$arguments =~ s/\s+$//;
				$arguments =~ s/\s+/ /g;
				push @extra, $arguments;
			}

			my $nodeID = "N" . ++$genID;
			my %rule = (
				#chain => $currChain,
				target => $target,
				id => $nodeID,
			);
			$rule{options} = $options unless $options =~ /^-*$/;
			$rule{input} = $input unless $input eq "*";
			$rule{output} = $output unless $output eq "*";
			$rule{source} = $source unless $source eq "0.0.0.0/0";
			$rule{destination} = $destination unless $destination eq "0.0.0.0/0";
			$rule{filter} = \@filter if @filter;
			$rule{extra} = \@extra if @extra;

			push @{$rules{$currChain} ||= []}, \%rule;  # add the rule

			$start{$currChain} ||= "S" . $genID;  # set the start if this is the first

			if (!defined $start{$target})
			{
				# This target has not been seen before.
				# Reserve the name.
				# This also ensures the chain will be rendered
				# even if it has no rules.
				$start{$target} = undef;
			}
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
	foreach my $chain (sort keys %start)
	{
		if ($KnownTarget{$chain} || $start{$chain})
		{
			# It is a standard target`or it has a startID
		}
		else
		{
			# It has a nodeID
			my $rules = $rules{$chain};
			if ($rules && @$rules)
			{
				# There are rules, but no startID. This is strange.
				print "ERROR: Chain '$chain' has no startID\n";
			}
			else
			{
				# There are no rules.
				print "WARNING: Chain '$chain' is empty\n";
				$rules{$chain} = [];
			}
			$start{$chain} = "S" . ++$genID;
		}
	}
	my (@nodes, @edges);
	foreach my $chain (sort keys %rules)
	{
		# Render first pseudo-node with chain name
		my $startID = $start{$chain};
		push @nodes, qq($startID [fillcolor="$ColorStart", style=filled shape=box label="$chain"]);
		my $prevID = $startID;
		my @items = ();  # node data objects

		my $rules = $rules{$chain};
		if ($rules && @$rules > 0)
		{
			# Preprocess rules
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
				my $filter = $$rule{filter};
				push @selector, "i=$input" if $input;
				push @selector, "o=$output" if $output;
				push @selector, "s=$source" if $source;
				push @selector, "d=$destination" if $destination;
				push @selector, join " ", @$filter if $filter;

				# Extra arguments
				my @extra;
				my $extra = $$rule{extra};
				push @extra, join " ", @$extra if $extra;

				# Add data as item
				push @items, {
					id       => $nodeID,
					target   => $target,
					selector => \@selector,
					extra    => \@extra,
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

			# Render items as nodes
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
		}

		# Render the end of the chain as a pseudo-node too
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
			# If the last rule does an unconditional jump, showing
			# the implicit return is superfluous.
			if (@items)
			{
				my $last = $items[-1];
				my ($sel, $ex, $tgt) = @$last{qw/selector extra target/};
				my $unconditional = (!$sel || !@$sel);
				my $def = $KnownTarget{$tgt};
				my $jump = !$def ||  # assume unknown targets are jumps
					$$def{terminating};  # or terminating targets
				if ($unconditional && $jump)
				{
					$targetType = undef;
				}
			}
		}
		if (defined $targetType)
		{
			my $endID = "E" . ++$genID;
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
	#my $temp_fname = "output-$name.gv"; open my $out_fh, ">", $temp_fname or die "Cannot open '$temp_fname': $!";
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

