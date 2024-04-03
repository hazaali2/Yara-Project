rule candidateRule22 {
  strings:
    $a = "blur"
    $b = { D2 }
  condition:
    $a at 0 and #b > 3
}
