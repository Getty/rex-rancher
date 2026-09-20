requires 'perl', '5.014004';
requires 'IO::K8s', '1.107';
requires 'JSON::MaybeXS';
requires 'Kubernetes::REST', '1.107';
requires 'Rex', '1.14.0';
requires 'Rex::LibSSH', '0.004';
requires 'YAML::PP';

on 'test' => sub {
  requires 'Test::More', '0.98';
};
