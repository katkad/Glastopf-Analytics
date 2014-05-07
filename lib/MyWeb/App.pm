package MyWeb::App;
use Dancer2;
use Geo::IP;
use Socket;
use DBI;


our $VERSION = '0.1';

set 'database'  =>  '/home/qqvavra2/glastopf.db';

sub connect_db {
    my $dbh = DBI->connect("dbi:SQLite:dbname=".setting('database')) or die $DBI::errstr;
    return $dbh;
}

get '/' => sub {
    template 'index.tt';
};

get '/top-files' => sub {
    my $db = connect_db();
    my $sql = 'SELECT COUNT(filename), filename FROM events WHERE filename is not null GROUP BY filename ORDER BY COUNT(filename) DESC LIMIT 10';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $files;
    while ( my @data = $sth->fetchrow_array() ) {
        my $count = $data[0];
        my $file = $data[1];
        $files.= "$count
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $file
                    <br><br>";
        }
    $sth->finish();
    template 'top-files.tt', {
        files => $files
    };
};

get '/last-files' => sub {
    my $db = connect_db();
    my $sql = 'SELECT time, filename FROM events WHERE filename is not null ORDER BY time DESC LIMIT 10';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $files;
    while ( my @data = $sth->fetchrow_array() ) {
        my $time = $data[0];
        my $file = $data[1];
        $files.= "$time
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $file
                    <br><br>";
        }
    $sth->finish();
    template 'last-files.tt', {
        files => $files
    };
};

get '/last-events' => sub {
    my $db = connect_db();
    my $sql = 'SELECT time, request_url, SUBSTR(source,-20,14) FROM events ORDER BY time DESC LIMIT 10';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $events;
    while ( my @data = $sth->fetchrow_array() ) {
        my $time			=	$data[0];
        my $request_url     =   $data[1];
        my $source_ip		=	$data[2];
        my $gi          	=	Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country         =   $gi->country_name_by_addr($source_ip);
        my $country_code	=	$gi->country_code_by_addr($source_ip);
        my $hostname		=	gethostbyaddr( inet_aton($source_ip), AF_INET );
        if ( defined($hostname) ) {
            # TODO: rewrite this
        }
        else {
            $hostname = "Unknown hostname";
        }
        if ( defined($country) ) {
            # TODO: rewrite this
        }
        else {
            $country = "Unknown country";
        }
        $events.= "$time
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $source_ip
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $country
                    <br>
                    <img src='/images/flags/flags_style4_tiny/$country_code.png'>
                    &nbsp;
                    $hostname
                    <br>
                    $request_url
                    <br><br>";
        }
    $sth->finish();
    template 'last-events.tt', {
        events => $events
    };
};

get '/top-visitors' => sub {
    my $db = connect_db();
    my $sql = 'SELECT COUNT(source), SUBSTR(source,-20,14) AS stripped FROM events GROUP BY stripped ORDER BY COUNT(stripped) DESC LIMIT 10';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $visitors;
    while ( my @data = $sth->fetchrow_array() ) {
        my $count           = $data[0];
        my $source_ip       = $data[1];
        my $gi              = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country         = $gi->country_name_by_addr($source_ip);
        my $country_code    = $gi->country_code_by_addr($source_ip);
        my $hostname        = gethostbyaddr( inet_aton($source_ip), AF_INET );
        if ( defined($hostname) ) {
            # TODO: rewrite this
        }
        else {
            $hostname = "Unknown hostname";
        }
        if ( defined($country) ) {
            # TODO: rewrite this
        }
        else {
            $country = "Unknown country";
        }
        $visitors.= "$count
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $source_ip
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $country
                    <br>
                    <img src='/images/flags/flags_style4_tiny/$country_code.png'>
                    &nbsp;
                    $hostname
                    <br><br>";
        }
    $sth->finish();
    template 'top-visitors.tt', {
        visitors => $visitors
    };
};

get '/top-countries' => sub {
    my $db = connect_db();
    my $sql = 'SELECT SUBSTR(source,-20,14) FROM events';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $countries;
    my %countries;
    my $country_code;
    my %country_codes;
    while ( my @data = $sth->fetchrow_array() ) {
        my $source_ip       = $data[0];
        my $gi              = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country         = $gi->country_name_by_addr($source_ip);
        my $country_code    = $gi->country_code_by_addr($source_ip);
        if ( defined($country) ) {
            $countries{$country}++;
            $country_codes{$country} = $country_code;
        }
        else {
            $country = "Unknown country";
            $countries{$country}++;
        }
    }
    my $i = 0;
    foreach my $country ( sort { $countries{$b} <=> $countries{$a}; } keys %countries ) {
        if ( $i == 10 ) { last(); }
        $countries.= "<img src='/images/flags/flags_style4_tiny/$country_codes{$country}.png'>
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $countries{$country}
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $country
                    <br><br>";
        $i++;
    }
    $sth->finish();
    template 'top-countries.tt', {
        countries => $countries
    };
};

get '/top-user-agents' => sub {
    my $db = connect_db();
    my $sql = 'SELECT request_raw FROM events';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my %seen = ();
    my $agents;
    while ( my @data = $sth->fetchrow_array() ) {
        my $request_raw = $data[0];
        if ( $request_raw =~ /User-Agent: (.*?)$/m ) {
            my $user_agent = $1;
            $seen{$user_agent}{count}++;
            $seen{$user_agent}{agent} = $user_agent;
        }
    }
    my $i = 0;
    for my $key ( sort { $seen{$b}->{count} <=> $seen{$a}->{count} } keys %seen ) {
        if ( $i == 10 ) { last(); }
        $agents.= "$seen{$key}{count}
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $seen{$key}{agent}
                    <br><br>";
        $i++;
    }
    $sth->finish();
    template 'top-user-agents.tt', {
        agents => $agents
    };
};

get '/top-event-patterns' => sub {
    my $db = connect_db();
    my $sql = 'SELECT count(pattern), pattern FROM events GROUP BY pattern ORDER BY count(pattern) DESC LIMIT 10';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $patterns;
    while ( my @data = $sth->fetchrow_array() ) {
        my $count   = $data[0];
        my $pattern = $data[1];
        $patterns.= "$count
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $pattern
                    <br><br>";
    }
    $sth->finish();
    template 'top-event-patterns.tt', {
        patterns => $patterns
    };
};

get '/top-requested-filetypes' => sub {
    my $db = connect_db();
    my $sql = 'SELECT count, content FROM filetype ORDER BY count DESC LIMIT 10';
    my $sth = $db->prepare($sql) or die $db->errstr;
    $sth->execute or die $sth->errstr;

    my $filetypes;
    while ( my @data = $sth->fetchrow_array() ) {
        my $count   = $data[0];
        my $filetype = $data[1];
        $filetypes.= "$count
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    $filetype
                    <br><br>";
    }
    $sth->finish();
    template 'top-requested-filetypes.tt', {
        filetypes => $filetypes
    };
};

true;
