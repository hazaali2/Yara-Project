rule candidateRule24 {
  strings:
    $a = "FILE"
    $b = { A9 F5 }
  condition:
    $a at 0 and #b > 0
}
