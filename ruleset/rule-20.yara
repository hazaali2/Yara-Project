rule candidateRule20 {
  strings:
    $a = "blur"
    $b = { 50 1C [0-100] 9E }
  condition:
    $a at 0 and $b
}
