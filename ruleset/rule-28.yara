rule candidateRule28 {
  strings:
    $a = "FILE"
    $b = { 37 79 }
  condition:
    $a in (0..200) and $b in (filesize-200..filesize)
}
