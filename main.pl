#!/usr/bin/perl
use strict;
use warnings;
use HTTP::Tiny; # https://perldoc.perl.org/HTTP/Tiny.html
use MIME::Base64; # remove this from the namespace
use URI::Escape; #  http://search.cpan.org/perldoc/URI::Escape

print "Ich beginne\n";

my $bSize = 16;

my $wante = 'PKCS#7 padding';

my $parm = 'G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJ3JtkSaJRrJwlP%2BDsbHXlYKSh%2FPMVHnhLmbzHIY7GAR1bVcy3Ix3D2Q5cVi8F6bmY%3D';
#my $parm = 'ULp-Dd93!!pZmzC6q7CnFh9AOMB6NdDJpT5FtFwdPAU4ctEYKuzA14gvyHodr60GOgXDSDIm2PFrp5jLvlQS5ofQGpTrPoQDGq4yl25-QEgSOsYTzV9XidDTHtXncxYmz25bKUDqCz3KZSI0xdbMcyRI7lxDWwtR5MLu!RHzANbyyZwnY037m66XCA-XjMzJbheQcjc5O5yLfLW9iwFDNA~~';

#$parm =~ s/-/+/ig;
#$parm =~ s/!/\//ig;
#$parm =~ s/~/=/ig;

# Find out if I can redact something automatically with git
my $url = 'http://natas28:REDACTED@natas28.natas.labs.overthewire.org/search.php/?query='; # Maybe I'm just being silly and natas28 doesn't even use cbc...
#my $url = 'REDACTED';
#

$parm = uri_unescape($parm);

$parm = decode_base64($parm);

my $qLen = length($parm);

my $it = 0;
while($it < 16){
    my $currentB = $qLen-($bSize+$it);
    my $byte = ord(substr($parm, $currentB, 1)) ;
    my $whBYTE = $byte;
    $byte++;
    print $it."\n";
    while($byte != $whBYTE){
        substr($parm, $currentB, 1) = chr($byte);
        my $tempQ =  uri_escape(encode_base64($parm, ''));
        #my $tempQ = encode_base64($parm, '');
        #$tempQ =~ s/\+/-/ig;
        #$tempQ =~ s/\//!/ig;
        #$tempQ =~ s/=/~/ig;
        my $response = HTTP::Tiny->new->get($url.$tempQ);
       if (not grep(/$wante/, $response->{content})){
            print $byte."\n".$response->{content}."\n";
            last
        }else{
            print "Nope: $byte\n\n";
        }
        $byte = ($byte + 1)%256;
    }
    $it++;
}
