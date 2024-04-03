rule candidateRule02 {
  strings:
    $a = "red!"
    $b = { FE C3 9C F4  85 F5 14 5C  B0 51 F5 B9 }
  condition:
    $a at 0 and $b
}
