rule candidateRule17 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { C4 79 D1 }
  condition:
    $a at 0 and $b
}
