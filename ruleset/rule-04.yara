rule candidateRule04 {
  strings:
    $a = { FE C3 [0-12] B0 51 }
  condition:
    $a
}
