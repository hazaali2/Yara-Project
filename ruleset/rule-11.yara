rule candidateRule11 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { E2 9C }
    $c = { DB 12 }
  condition:
    $a at 0 and $b and $c
}
