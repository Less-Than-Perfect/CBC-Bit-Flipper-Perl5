#!/usr/bin/env perl
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

#my @wante = ('ValueError: Padding is incorrect.', 'ValueError: PKCS#7 padding is incorrect.');

#my @wante = ('Padding', 'Incorrect amount of PKCS#7');

my @wante = ('^FLAG^1d6c98018131f055d327e9e6eeb7ac26e69cdeb3b3cc90b1bd3f36a1fb15c135$FLAG$', 'padding', 'Incorrect');

#my $parm = 'IKwfTKjlaMCMq0daFlELtRPCxt5ldMJWTSmDCO5ZnP8La0MKyjtBxEuAFVAJB0Y26mdhRIgv7rcQWFLMloNSD4blyRIVlXF07hDNDbfOFdY%3D';
#my $parm = 'G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPIi9jK6%2FhBGgtXoRbG6b%2BPmSHmaB7HSm1mCAVyTVcLgDq3tm9uspqc7cbNaAQ0sTFc%3D';
my $parm = 'mSs15EVMapI0hqS91gf6RSlfyg1NLECjzts1b2yQ9lrSg5noe0vywjaYlKjSdC7rwtLe!j9SczoAcTGWRAwflcdu1CHfjG9GPnqzY1u3CyVPP8tU!VjGQxTLGTihjrutUE7lp7Q6WYBZXSryI7Kab6bHWiXQMZe04z6SdjhI87H43fLp5ZG5NwGXdwPTLzR12zoGYxBgOMHrResSFX-vbw~~';

$parm =~ s/-/+/ig;
$parm =~ s/!/\//ig;
$parm =~ s/~/=/ig;

#my $url = 'http://127.0.0.1:5000/?cte=';
# Figure out how to redact stuff like this for future reference
#my $url = 'http://natas28:JWwR438wkgTsNKBbcJoowyysdM82YjeF@natas28.natas.labs.overthewire.org/search.php/?query='; # Whoops I didn't mean to post this, but I guess since Its already on the interwebs not much point in removing instantly.
#

my $url = 'http://34.74.105.127/b06a7c2a37/?post=';

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

my $target = 0;
my $bNum = ($qLen+1)/$bSize;
print "\nPadding Size: $AIM\n\nNumber of Blocks: $bNum\n";
my $bt = 0;
while ($bt < $bNum){
    $target = $AIM+1;
    $it = $AIM;
    print "block = $bt\n";
    while($it < $bSize){
        $tempPARM = $parm;
        prep( );
        $currentB = $qLen-($bSize+$it);
        my $ogByte = ord(substr($parm, $currentB, 1));
        my $byte = ord(substr($parm, $currentB, 1)) ;
        my $whBYTE = $byte;
        $byte = ($byte + 1)%255; 
        while($byte != $whBYTE){
            substr($tempPARM, $currentB, 1) = chr($byte);
            $return = getRequest($tempPARM);
            if ($return == 1){
                my $xD = $byte^$ogByte^$target;
                push @text, $xD;
                $AIM++;
                $target++;
                last;
            }else{ # Add some error checking code for when 1 is never returned.
                $byte = ($byte + 1)%255; 
            }
        }
        $it++;
    }
    $qLen = $qLen-$bSize;
    $parm = substr($parm,  0, $qLen+1); # Add 1 because it starts from 1 instead of 0.
    $bt++;
    $AIM = 0;
    my @plainText = reverse(@text);
    foreach( @plainText ){
        print chr($_);
    } 
print "\n\n";
}
print "\n";

print "done\n";
my @plainText = reverse(@text);
foreach( @plainText ){
    print chr($_);
} 
print "\n\n";

sub prep { # Prep paddings (turns something like \x03\x03\x03 to \x04\x04\x04)
    my $tilAIM = 0;
    while ($tilAIM < $AIM){
        $currentB = $qLen-($bSize+$tilAIM);
        substr($tempPARM, $currentB, 1) = chr(ord(substr($parm, $currentB, 1))^$target^$text[$tilAIM+$bt*$bSize]);
        $tilAIM++;
    }
}

sub getRequest {
    my $heel = uri_escape(encode_base64($_[0], ''));
    my $response = HTTP::Tiny->new->get($url.$heel);
    if (not any {$response->{content} =~ $_ } @wante){
        return 1;
    }
    else{
        return 0;
    }
}