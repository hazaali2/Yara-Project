rule candidateRule10 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { B8 CA }
  condition:
    $a at 0 and $b
}
