rule candidateRule25 {
  strings:
    $a = "FILE"
    $b = { DC DD [0-32] CD }
  condition:
    $a at 0 and $b
}
