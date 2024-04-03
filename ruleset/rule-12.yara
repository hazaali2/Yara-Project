rule candidateRule12 {
  strings:
    $a = { 46 49 4C 45 }
    $b = { C3 13 }
    $c = { BA 55 }
  condition:
    $a at 0 and $b and $c
}
