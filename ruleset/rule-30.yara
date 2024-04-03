rule candidateRule30 {
  strings:
    $a = "FILE"
    $b = { DC }
  condition:
    $a in (0..200) and $b in (filesize-200..filesize)
}
