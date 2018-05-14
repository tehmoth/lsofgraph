#!/usr/bin/env perl
use strict;
use warnings;
use B;

=begin comment

  a    file access mode
  c    process command name (all characters from proc or user structure)
  C    file structure share count
  d    file's device character code
  D    file's major/minor device number (0x<hexadecimal>)
  f    file descriptor (always selected)
  F    file structure address (0x<hexadecimal>)
  G    file flaGs (0x<hexadecimal>; names if +fg follows)
  g    process group ID
  i    file's inode number
  K    tasK ID
  k    link count
  l    file's lock status
  L    process login name
  m    marker between repeated output
  n    file name, comment, Internet address
  N    node identifier (ox<hexadecimal>
  o    file's offset (decimal)
  p    process ID (always selected)
  P    protocol name
  r    raw device number (0x<hexadecimal>)
  R    parent process ID
  s    file's size (decimal)
  S    file's stream identification
  t    file's type
  T    TCP/TPI information, identified by prefixes (the
       `=' is part of the prefix):
           QR=<read queue size>
           QS=<send queue size>
           SO=<socket options and values> (not all dialects)
           SS=<socket states> (not all dialects)
           ST=<connection state>
           TF=<TCP flags and values> (not all dialects)
           WR=<window read size>  (not all dialects)
           WW=<window write size>  (not all dialects)
       (TCP/TPI information isn't reported for all supported
         UNIX dialects. The -h or -? help output for the
         -T option will show what TCP/TPI reporting can be
         requested.)
  u    process user ID
  z    Solaris 10 and higher zone name
  Z    SELinux security context (inhibited when SELinux is disabled)
  0    use NUL field terminator character in place of NL
  1-9  dialect-specific field identifiers (The output of -F? identifies the information to be found in dialect-specific fields.)

=end comment

=cut

=pod

=over

=item parse_lsof 

Parse lsof output into lua tables

=back

=cut

sub parse_lsof {
	my $fh = shift;

	my %procs;

	my ($cur, $proc, $file);

	while (defined(my $l = <$fh>)) {
		chomp($l);

		die "Unexpected input, did you run lsof with the '-F' flag?\n" if $l =~ m{^COMMAND};
		my (undef, $tag, $val) = split /^(.)/ => $l;

		if ($tag eq 'p') {
			if (!$procs{$val}) {
				$proc = { files => [] };
				undef $file; 
				$cur = $proc;
				$procs{$val} = $proc;
			} else {
				undef $proc;
				undef $cur;
			}
		} elsif ($tag eq 'f' && $proc) {
			$file = { proc => $proc };
			$cur = $file;
			push @{ $proc->{files} }, $file;
		}
	
		$cur->{$tag} = $val if $cur;
		
		# skip kernel threads

		if ($proc) {
			if ($file and %$file and $file->{t} && $file->{f} eq "txt" and $file->{t} eq "unknown") {
				undef $procs{ $proc->{p} };
				undef $proc; 
				undef $file;
				undef $cur;
			}
		}

	}

	return \%procs;
}


sub find_conns {
	my ($procs) = @_;

	my %cs = (
		fifo => {}, #  index by inode
		unix => {}, # index by inode
		tcp  => {}, # index by sorted endpoints
		udp  => {}, # index by sorted endpoints
		pipe => {}, # index by sorted endpoints
	);

	for my $pid (sort { $a <=> $b } keys %$procs) {
		my $proc = $procs->{ $pid };
		for my $file (@{ $proc->{files} || [] }) {
			next unless $file->{t};
			if ($file->{t} eq "unix") {
				my $us = $cs{unix};
				my $i = $file->{i} || $file->{d};
				$us->{$i} ||= [];
				push @{ $us->{$i} }, $file;
			}

			if ($file->{t} eq "FIFO") {
				my $fs = $cs{fifo};
				$fs->{ $file->{i} } ||= [];	
				push @{ $fs->{ $file->{i} } }, $file;
			}

			if ($file->{t} eq "PIPE") { # BSD/MacOS
				my $n = *1;
				for (my $n = *1; $file->{n} =~ m{->(.+)}gc;) {
					my @ps = sort $file->{d}, $$n;
					my $id = join '\n', @ps;
					my $fs = $cs{pipe};
					$fs->{ $id } ||= [];
					push @{ $fs->{$id} }, $file;
				}
			}

			if ($file->{t} =~ m{^IPv[46]$}) { 
				#use warnings FATAL => 'all';
				my @ps = sort grep defined, $file->{n} =~ m{^(.+?)(?:->(.+?))?$};
				my $id = join '\\n' => @ps;
				my $fs = $file->{P} eq 'TCP' ? $cs{tcp} : $cs{udp};
				$fs->{$id} ||= [];
				push @{ $fs->{$id} }, $file;
			}
		}
	}

	return \%cs;

}



my $procs = parse_lsof(*STDIN);
my $conns = find_conns($procs);

# Generate graph

print <<HEADER;
digraph G {
	graph [ center=true, margin=0.2, nodesep=0.1, ranksep=0.3, rankdir=LR];
	node [ shape=box, style=\"rounded,filled\" width=0, height=0, fontname=Helvetica, fontsize=10];
	edge [ fontname=Helvetica, fontsize=10];
HEADER

# Parent/child relationships

for my $pid (sort { $a <=> $b } keys %$procs) {
	my $proc = $procs->{$pid};
	my $color = ($proc->{R}||0) == 1 ? "grey70" : "white";
	next unless $proc && %$proc;
	printf qq{	p%d [ label = "%s\\n%d %s" fillcolor=%s ];\n} 
		=> $proc->{p}, ($proc->{n} || $proc->{c}), $proc->{p}, $proc->{L}, B::cstring($color);

	if ($proc->{R} and defined $procs->{$proc->{R}}) {
		my $proc_parent = $procs->{$proc->{R}};
		if ($proc_parent->{p} != 1) {
			printf qq{	p%d -> p%d [ penwidth=2 weight=100 color=grey60 dir="none" ];\n}
				=> @$proc{qw/R p/};
		}
	}
}


# Connections

my %colors = (
	fifo => "green",
	unix => "purple",
	tcp  => "red",
	udp  => "orange",
	pipe => "orange",
);

for my $type (sort keys %$conns) {
	my $conn = $conns->{$type};
	for my $id (sort keys %$conn) {
		my $files = $conn->{$id};

		# one-on-one connections
		
		if ($#$files == 1) {

			my ($f1, $f2) = @$files;
			my ($p1, $p2) = map( $_->{proc}, @$files);
			
			if ($p1 != $p2) {
				my $label = $type . ':\n' . $id;
				my $dir = "both";
				if ($f1->{a} eq "w") {
					$dir = "forward"
				}
				elsif ($f1->{a} eq "r") {
					$dir = "backward";
				}
				printf qq{	p%d -> p%d [ color="%s" label="%s" dir="%s"];\n} 
					=> $p1->{p}, $p2->{p}, $colors{$type} || "black", $label, $dir;
			}

		}
	}
}

# Done

printf "}\n";
