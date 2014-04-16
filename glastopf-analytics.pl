#!/usr/bin/perl

# Glastopf Analytics v1.0
# Author: Kamil Vavra (www.xexexe.cz)
# Credits to Johannes Schroeter (http://devwerks.net/en/research/tools/)

use strict;
use warnings;

use DBI;
use Geo::IP;

my $dbname = "/opt/myhoneypot/db/glastopf.db";

my $dbh = DBI->connect(          
    "dbi:SQLite:dbname=$dbname",               
    { RaiseError => 1 } 
) or die $DBI::errstr;

    until ( my $todo ) {                   
    header();
    print "* What to do?\n";
    print "* * * * * * *\n";
    print "*\n";
    print "* 1) Show last 10 events\n";
    print "* 2) Show top 10 countries\n";
    print "* 3) Show top 10 user-agents\n";
    print "* 4) Show top 10 event patterns\n"; 
    print "* 5) exit\n*\n";

    print "* Enter number of your choice (1-5): ";
    chomp( my $input = <> );

    if ( $input eq "1" ) {
    header();
    print "* Show last 10 events\n";
    print "* * * * * * * * * * *\n*\n";
    last_ten_events(); 
    press_any_key();     
    }    
    elsif ( $input eq "2" ) {
    header();
    print "* Show top 10 countries\n";
    print "* * * * * * * * * * * *\n*\n";
    top_ten_countries();
    press_any_key();                
    }
    elsif ( $input eq "3" ) {
    header();
    print "* Show top 10 user-agents\n";
    print "* * * * * * * * * * * * *\n*\n";
    top_ten_agents();
    press_any_key();                      
    }
    elsif ( $input eq "4" ) {
    system("clear");
    print "* Show top 10 event patterns\n";
    print "* * * * * * * * * * * * * * *\n*\n";
    top_ten_patterns();
    press_any_key();                   
    }
    elsif ( $input eq "5" ) {
    system("clear");
    print "\n* Press any key to continue.";
    <>;
    system("clear");                     
    }
    elsif ( $input eq "6" ) {
    header();
    print "* You are awesome - thank you\n";
    print "* * * * * * * * * * * * * * *\n\n";
    last;   
    }                      
    else {
    print "\n* Whaat? Try again:";                
    } 
}
$dbh->disconnect();

sub header {
    system("clear");
    print "* * * * * * * * * * * * * * * * * * * * * * * * * * * *\n";
    print "* Glastopf Analytics :: easy honeypot statistics v1.0 *\n";
    print "*  Kamil Vavra; www.xexexe.cz; vavkamil(at)gmail.com  *\n";
    print "* * * * * * * * * * * * * * * * * * * * * * * * * * * *\n";
}

sub press_any_key {
    print "*\n* Press any key to continue.";
    <>;
}

sub last_ten_events {
    my $sth = $dbh->prepare( "SELECT time, request_url, SUBSTR(source,-20,14) FROM events ORDER BY time DESC LIMIT 10" );  
    $sth->execute();

    while (my @data = $sth->fetchrow_array()) {
        my $time = $data[0]; 
        my $request_url = $data[1]; 
        my $source_ip = $data[2]; 
        my $gi = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country = $gi->country_name_by_addr($source_ip);
        printf ("* %-22s %-17s %-15.25s %s\n", $time, $source_ip, $country, $request_url);
    }
$sth->finish();
}

sub top_ten_countries {
    my $sth = $dbh->prepare( "SELECT SUBSTR(source,-20,14) FROM events" );  
    $sth->execute();

    my %countries;
    while (my @data = $sth->fetchrow_array()) {
        my $source_ip = $data[0];
        my $gi = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country = $gi->country_name_by_addr( $source_ip );
        if (defined($country)) {
            $countries{ $country }++;
        } else {
            $country = "Unknown";
            $countries{ $country }++;
        }
    }
    $sth->finish();
    my $i = 0;
    foreach my $source_ip ( sort { $countries{$b}<=> $countries{$a}; } keys %countries ) {
        if($i == 10) { last(); }
        printf "* %6d %s\n", $countries{ $source_ip }, $source_ip;
        $i++;
    }
}

sub top_ten_agents {
    my %seen = ();
    my $sth = $dbh->prepare( "SELECT request_raw FROM events" );  
    $sth->execute();

    while (my @data = $sth->fetchrow_array()) {
        my $request_raw  = $data[0]; 
        if ($request_raw =~ /User-Agent: (.*?)$/m) {
            my $user_agent = $1;
            $seen{$user_agent}{count}++;
            $seen{$user_agent}{agent} = $user_agent;
        }
    }
    my $i = 0;
    for my $key ( sort {$seen{$b}->{count} <=> $seen{$a}->{count}} keys %seen ) {
        if($i == 10) { last(); }
        print "* $seen{$key}{count} events, $seen{$key}{agent}\n";
        $i++;
    }
    $sth->finish();
}

sub top_ten_patterns {
    my $sth = $dbh->prepare( "SELECT count(pattern), pattern FROM events GROUP BY pattern ORDER BY count(pattern) desc LIMIT 10" );  
    $sth->execute();

    while (my @data = $sth->fetchrow_array()) {
        my $count = $data[0];
        my $pattern = $data[1];  
        printf ("* %6d %s\n", $count, $pattern); 
    }
$sth->finish();
}