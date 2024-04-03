rule candidateRule23 {
  strings:
    $a = "blur"
    $b = { A9 F5 }
  condition:
    $a at 0 and #b > 0
}
