rule candidateRule06 {
  strings:
    $a = "red!"
    $b = { FE C3 }
  condition:
    $a and $b
}
