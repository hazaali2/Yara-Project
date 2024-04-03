rule candidateRule08 {
  strings:
    $a = "red!"
    $b = { FB 8E 8D }
  condition:
    $a at 0 and $b
}
