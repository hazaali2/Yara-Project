rule candidateRule27 {
  strings:
    $a = "FILE"
    $b = { DA C4 }
  condition:
    $a in (0..200) and $b in (200..filesize)
}
