rule candidateRule21 {
  strings:
    $a = "blur"
    $b = { B1 91 [0-120] C1 }
  condition:
    $a at 0 and $b
}
