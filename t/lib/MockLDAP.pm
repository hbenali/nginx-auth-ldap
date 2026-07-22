package MockLDAP;

use strict;
use warnings;
use IO::Socket::INET;
use Convert::ASN1 qw(asn_encode asn_decode);

# A minimal mock LDAP server for testing nginx-auth-ldap
# Supports: bind (simple), search (single-entry response)

my $ldap_port = 8389;

sub new {
    my ($class) = @_;
    my $self = {
        users => {},  # dn => password
        entries => {}, # dn => { attrs => { name => [values] } }
        running => 0,
    };
    bless $self, $class;
    return $self;
}

sub add_user {
    my ($self, $dn, $password, %attrs) = @_;
    $self->{users}{$dn} = $password;
    $self->{entries}{$dn} = {
        dn => $dn,
        attrs => {},
    };
    while (my ($k, $v) = each %attrs) {
        $self->{entries}{$dn}{attrs}{$k} = ref($v) eq 'ARRAY' ? $v : [$v];
    }
    return $self;
}

sub start {
    my ($self) = @_;

    $self->{sock} = IO::Socket::INET->new(
        LocalPort => $ldap_port,
        Listen    => 5,
        ReuseAddr => 1,
        Proto     => 'tcp',
    ) or die "MockLDAP: Cannot bind to port $ldap_port: $!";

    $self->{running} = 1;
    print "# MockLDAP: Listening on port $ldap_port\n";

    while ($self->{running}) {
        my $client = $self->{sock}->accept();
        next unless $client;
        $self->_handle_client($client);
    }
}

sub _handle_client {
    my ($self, $client) = @_;

    while (1) {
        # Read BER-encoded LDAP message
        my $buf;
        my $n = $client->read($buf, 2, 0);
        last unless defined $n && $n == 2;

        my ($tag, $len) = unpack('CC', $buf);

        my $remaining = $len;
        if ($len >= 0x80) {
            my $llen = $len & 0x7f;
            my $lbuf;
            $client->read($lbuf, $llen, 2);
            $remaining = 0;
            for (my $i = 0; $i < $llen; $i++) {
                $remaining = ($remaining << 8) | ord(substr($lbuf, $i, 1));
            }
        }

        my $data;
        if ($remaining > 0) {
            $client->read($data, $remaining);
        }
        last unless defined $data;

        # Parse LDAP message
        my $msg = $self->_parse_ldap_message($buf, $data);
        next unless $msg;

        my $response = $self->_process_message($msg);
        if ($response) {
            $client->send($response);
        }
    }

    $client->close();
}

sub _parse_ldap_message {
    my ($self, $header, $data) = @_;

    # Very simplified LDAP BER parsing for testing
    # LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { ... } }
    # We just look at the basic structure

    my $pos = 0;
    return {} if length($data) < 6;

    my $b1 = ord(substr($data, 0, 1)); # SEQUENCE tag

    # Find messageID (INTEGER, tag 0x02)
    for (my $i = 1; $i < length($data); $i++) {
        my $tag = ord(substr($data, $i, 1));
        if ($tag == 0x02) {
            $pos = $i + 1;
            my $idlen = ord(substr($data, $pos, 1));
            my $msgid = 0;
            for (my $j = 0; $j < $idlen; $j++) {
                $msgid = ($msgid << 8) | ord(substr($data, $pos + 1 + $j, 1));
            }
            $pos += 1 + $idlen;

            # Find the protocolOp (could be bindRequest 0x60, searchRequest 0x63)
            my $optag = ord(substr($data, $pos, 1));
            my $oplen = ord(substr($data, $pos + 1, 1));
            my $opdata = substr($data, $pos + 2, $oplen);

            return {
                msgid => $msgid,
                optag => $optag,
                opdata => $opdata,
            };
        }
    }

    return {};
}

sub _process_message {
    my ($self, $msg) = @_;

    my $msgid = $msg->{msgid} || 1;
    my $optag = $msg->{optag} || 0;
    my $opdata = $msg->{opdata} || '';

    # bindRequest (0x60)
    if ($optag == 0x60) {
        return $self->_handle_bind($msgid, $opdata);
    }
    # searchRequest (0x63)
    elsif ($optag == 0x63) {
        return $self->_handle_search($msgid, $opdata);
    }

    return undef;
}

sub _handle_bind {
    my ($self, $msgid, $data) = @_;

    # Extract bind DN and credentials from the raw data
    # We'll be permissive - any bind succeeds if DN exists and password matches

    my $dn = '';
    my $password = '';

    # Simple approach: extract strings from BER
    my @strings = _extract_ber_strings($data);

    if (@strings >= 2) {
        $dn = $strings[0];
        $password = $strings[1];
    }

    print "# MockLDAP: Bind request dn='$dn'\n";

    my $result_code;
    if (exists $self->{users}{$dn}) {
        my $expected = $self->{users}{$dn};
        if ($password eq $expected || $password eq '') {
            $result_code = 0; # LDAP_SUCCESS
        } else {
            $result_code = 49; # LDAP_INVALID_CREDENTIALS
        }
    } elsif ($dn eq '' || $dn eq 'cn=admin,dc=example,dc=com') {
        # Default admin bind succeeds
        $result_code = 0;
    } else {
        $result_code = 49; # invalid credentials
    }

    # Build bindResponse
    return _build_ldap_result($msgid, 0x61, $result_code, '', '');
}

sub _handle_search {
    my ($self, $msgid, $data) = @_;

    my @strings = _extract_ber_strings($data);

    print "# MockLDAP: Search request strings: @strings\n";

    # Try to find a matching entry
    my $response = '';

    foreach my $dn (sort keys %{$self->{entries}}) {
        my $entry = $self->{entries}{$dn};

        # Build searchResultEntry
        my $entry_data = _build_ber_octet_string(ord(substr($dn, 0, 1)) == 0 ? substr($dn, 1) : $dn);

        # Build partial attribute list
        my $attr_data = '';
        while (my ($k, $vals) = each %{$entry->{attrs}}) {
            my $type_data = _build_ber_octet_string($k);
            my $vals_data = '';
            foreach my $v (@$vals) {
                $vals_data .= _build_ber_octet_string($v);
            }
            $vals_data = chr(0x31) . chr(length($vals_data)) . $vals_data; # SET
            $attr_data .= chr(0x30) . chr(length($type_data . $vals_data)) . $type_data . $vals_data; # SEQUENCE
        }
        $entry_data .= chr(0x30) . chr(length($attr_data)) . $attr_data; # partialAttributeList

        $response .= chr(0x64) . chr(length($entry_data)) . $entry_data; # searchResultEntry
    }

    # Always add searchResultDone
    $response .= _build_ldap_result($msgid, 0x65, 0, '', '');

    return $response;
}

sub _extract_ber_strings {
    my ($data) = @_;
    my @strings;
    my $pos = 0;

    while ($pos < length($data)) {
        my $tag = ord(substr($data, $pos, 1));
        $pos++;

        if ($pos >= length($data)) { last; }

        my $len = ord(substr($data, $pos, 1));
        $pos++;

        if ($len >= 0x80) {
            my $llen = $len & 0x7f;
            $len = 0;
            for (my $i = 0; $i < $llen; $i++) {
                $len = ($len << 8) | ord(substr($data, $pos, 1));
                $pos++;
            }
        }

        if ($pos + $len <= length($data)) {
            if ($tag == 0x04) { # OCTET STRING
                push @strings, substr($data, $pos, $len);
            }
            $pos += $len;
        } else {
            last;
        }
    }

    return @strings;
}

sub _build_ber_octet_string {
    my ($str) = @_;
    my $len = length($str);
    return chr(0x04) . chr($len) . $str;
}

sub _build_ldap_result {
    my ($msgid, $tag, $result_code, $matched_dn, $error_msg) = @_;

    my $result_code_enc = chr(0x0a) . chr(1) . chr($result_code); # ENUMERATED
    my $matched_dn_enc = $matched_dn ne '' ? _build_ber_octet_string($matched_dn) : '';
    my $error_msg_enc = $error_msg ne '' ? _build_ber_octet_string($error_msg) : '';

    my $op_data = $result_code_enc . $matched_dn_enc . $error_msg_enc;
    my $op_len = length($op_data);

    my $msgid_enc = chr(0x02) . chr(1) . chr($msgid);
    my $protocol_op = chr($tag) . chr($op_len) . $op_data;
    my $ldap_msg = chr(0x30) . chr(length($msgid_enc . $protocol_op)) . $msgid_enc . $protocol_op;

    return $ldap_msg;
}

sub stop {
    my ($self) = @_;
    $self->{running} = 0;
    if ($self->{sock}) {
        $self->{sock}->close();
    }
}

1;
