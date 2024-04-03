rule candidateRule18 {
  strings:
    $a = { 41 41 41 41 }
    $b = { 56 47 }
  condition:
    $a at 0 and $b
}
