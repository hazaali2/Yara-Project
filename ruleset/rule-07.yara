rule candidateRule07 {
  strings:
    $a = "red!"
    $b = { 06 D0 }
  condition:
    $a and $b
}
