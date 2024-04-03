rule candidateRule09 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { 8E 8D }
  condition:
    $a at 0 and $b
}
