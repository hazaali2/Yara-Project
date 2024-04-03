rule candidateRule05 {
  strings:
    $a = { FE C3 }
  condition:
    $a
}
