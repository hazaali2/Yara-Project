rule candidateRule01 {
  strings:
    $a = "FILE"
    $b = "red"
  condition:
    $a and $b at 0
    /* $a */
}
