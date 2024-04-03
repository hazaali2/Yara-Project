rule candidateRule26 {
  strings:
    $a = "FILE"
    $b = { DA C4 [0-24] 24 }
  condition:
    $a at 0 and $b
}
