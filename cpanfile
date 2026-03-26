requires 'perl', '5.014004';
requires 'Rex', '1.14';

recommends 'Rex::GPU';

on 'test' => sub {
  requires 'Test::More', '0.98';
};
