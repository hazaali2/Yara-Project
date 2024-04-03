rule candidateRule14 {
  strings:
    $a = { 41 41 41 41 }
    $b = { B2 C3 88 6A }
    $c = { CC 77 }
  condition:
    $a at 0 and $b and $c
}
