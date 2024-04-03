rule candidateRule13 {
  strings:
    $a = { 41 41 41 41 }
    $b = { C3 13 }
    $c = { BA 55 }
  condition:
    $a at 0 and $b and $c
}
