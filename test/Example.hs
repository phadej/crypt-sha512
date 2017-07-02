{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import System.POSIX.Crypt
import System.POSIX.Crypt.SHA512

import Data.Monoid ((<>))

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances ()

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

main :: IO ()
main = do
    let enc = crypt "pass" "$6$saltstring"
    isGlibc <- if fmap BS.length enc == Just 100
        then return True
        else do
            putStrLn $ "crypt doesn't recognize $6$ prefix in salt"
            putStrLn $ "returned " ++ show enc
            putStrLn $ "most likely you don't have glibc >=2.17"
            putStrLn $ "we will skip some tests"
            return False

    defaultMain $ testGroup "Tests" $
        [ sha512examples "cryptSHA512" cryptSHA512
        , cryptSHA512RawExamples
        ] ++ glibcTests isGlibc

  where
    glibcTests True =
        [ sha512examples "crypt" crypt
        , testProperty "glibc and native impl comparison" glibcNativeProp
        ]
    glibcTests False = []

glibcNativeProp :: Input -> Property
glibcNativeProp (Input key salt) =
    crypt key salt === cryptSHA512 key salt

data Input = Input BS.ByteString BS.ByteString
  deriving Show

instance Arbitrary Input where
    arbitrary = do
        key <- fmap BS.pack $ listOf $ elements $ BS.unpack alphabet
        salt <- fmap BS.pack $ listOf $ elements $ BS.unpack alphabet

        return (Input key $ "$6$" <> salt)
      where
        alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

sha512examples
    :: String
    -> (BS.ByteString -> BS.ByteString -> Maybe BS.ByteString)  -- crypt function
    -> TestTree
sha512examples name c = testGroup name $
    [ m "$6$saltstring"
        "Hello world!"
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    , m "$6$rounds=10000$saltstringsaltstring"
        "Hello world!"
        "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
    , m "$6$rounds=5000$toolongsaltstring"
        "This is just a test"
        "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
    , m "$6$rounds=1400$anotherlongsaltstring"
        "a very much longer text to encrypt.  This one even stretches over morethan one line."
        "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
    , m "$6$rounds=77777$short"
        "we have a short salt string but not a short password"
        "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
    , m "$6$rounds=123456$asaltof16chars.."
        "a short string"
        "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
    , m "$6$rounds=10$roundstoolow"
        "the minimum number is still observed"
        "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."
    -- regressions
    , m "$6$saltstring"
        "xXHJ"
        "$6$saltstring$RiyF6qtDbUHgB5fPL.afjplfUYs7h6e8AC8OGC1IZ0ZzQQuh6BWLwaGzlxnl2cSJ8kQvEGUxj4mwH/DosJPzx/"
    , m "$6$saltstring"
        "xyny33AP6"
        "$6$saltstring$Ev29zY/SO64MAYRTBEO3wrxXeeGGNxagYNWDK3Mh2Zucgx3d1Y7/i4tWvHd86WIDLH2iLaZByx3GRvaikhBpb."
    , m "$6$saltstring"
        "xyny33AP6!"
        "$6$saltstring$nsREMPgSFfMi0atBqyK8d78dtjt2IdZP4ih2hE38sTshzqC8D5E5wFBUxT9eN/gEos64NxxhUQzDaAyqogHUL0"
    ]
  where
    m salt key expected = testCase (BS8.unpack salt) $ do
        c key salt @?= Just expected

cryptSHA512RawExamples :: TestTree
cryptSHA512RawExamples = testGroup "cryptSHA512Raw"
    [ m Nothing "saltstring"
        "Hello world!"
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    , m (Just 10000) "saltstringsaltstring"
        "Hello world!"
        "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
    , m (Just 5000) "toolongsaltstring"
        "This is just a test"
        "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
    , m (Just 1400) "anotherlongsaltstring"
        "a very much longer text to encrypt.  This one even stretches over morethan one line."
        "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
    , m (Just 77777) "short"
        "we have a short salt string but not a short password"
        "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
    , m (Just 123456) "asaltof16chars.."
        "a short string"
        "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
    , m (Just 10) "roundstoolow"
        "the minimum number is still observed"
        "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."
    ]
  where
    m rounds salt key expected = testCase (BS8.unpack salt ++ " " ++ show rounds) $ do
        cryptSHA512Raw rounds key salt @?= expected
