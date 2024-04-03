rule candidateRule03 {
  strings:
    $a = "red!"
    $b = { FE C3 [0-12] B0 51 }
  condition:
    $a at 0 and $b
}
