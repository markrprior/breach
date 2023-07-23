#!/usr/bin/env perl
#

use LWP::UserAgent;
use JSON;

$AGENT = 'breach';
$TIMEOUT = 5;

my $ua = LWP::UserAgent->new;
$ua->agent($AGENT);
$ua->protocols_allowed( [ 'http', 'https'] );
$ua->max_redirect(0);
$ua->timeout($TIMEOUT);

my $req = HTTP::Request->new('GET', 'https://haveibeenpwned.com/api/v3/breaches');
$req->header('Accept' => 'application/json');
my $res = $ua->request($req);
if ( $res->is_success ) {
	my $json = eval { decode_json($res->decoded_content) };

	# If it's not json then we don't want to know about it ...
	return undef if $@;

	if ( ref($json) eq 'ARRAY' ) {
		my $uri = '/.well-known/security.txt';
		foreach my $x ( @{$json} ) {
			next unless $x->{Domain} ne '';
			my $breach = HTTP::Request->new('GET', 'https://www.' . $x->{Domain} . $uri);
			$breach->header('Accept' => 'text/plain');
			$result = $ua->request($breach);
			if ( $result->is_success ) {
				my $content = $result->decoded_content();
				if ( $content !~ /^\s*$/
					&& $content !~ /^\s*<!doctype html>/i
					&& $content !~ /^\s*<html>/i
					&& $content !~ /^\s*<head>/i ) {
					$content{$x->{Domain}} = $content;
					print $x->{Domain}, "\n", $content{$x->{Domain}}, "\n\n";
					$check{$x->{Domain}} = $x->{Title};
				}
			}
		}
	} else {
		print "json should have been an ARRAY\n";
	}
} else {
	printf "problem: %s\n", $res->status_line;
}
printf "\nCheck these %d domains\n", scalar keys %check;
foreach $i ( sort keys %check ) {
	printf "%s - %s\n", $i, $check{$i};
}
exit 0;
