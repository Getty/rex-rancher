requires 'perl', '5.014004';
requires 'HTTP::Tiny';
requires 'IO::K8s', '1.108';
requires 'IO::Socket::SSL';
requires 'JSON::MaybeXS';
requires 'Kubernetes::REST', '1.108';
requires 'Moo';
requires 'namespace::autoclean';
requires 'Rex', '1.14.0';
recommends 'Rex::GPU', '0.002';
recommends 'Rex::LibSSH', '0.004';
requires 'YAML::PP';

on 'test' => sub {
  requires 'Test::More', '0.98';
};
