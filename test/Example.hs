{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import System.POSIX.Crypt

assert :: String -> Bool -> IO ()
assert _ True    = return ()
assert msg False = fail msg

main :: IO ()
main = do
  -- basic usage
  enc <- maybe (fail "failed crypt") return $ crypt "password" "xx"
  print enc

  -- glibc2 extension
  enc2 <- maybe (fail "failed crypt") return $ crypt
      "password"
      -- 6 for SHA-512, since glibc 2.7
      "$6$somesalt$"
  print enc2

  enc2' <- maybe (fail "failed crypt") return $ crypt
      "password"
      enc2 -- using encrypted password as a salt
  print enc2'
  assert "sha512: doesn't match" $ enc2 == enc2'

  -- wrong salt
  assert "unexpected success" $ Nothing == crypt "password" ""

