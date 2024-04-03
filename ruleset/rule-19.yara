rule candidateRule19 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { 50 1C [0-100] 9E }
  condition:
    $a at 0 and $b
}
