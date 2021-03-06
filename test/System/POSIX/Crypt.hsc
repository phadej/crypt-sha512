 {-# LANGUAGE Trustworthy, CApiFFI #-}
module System.POSIX.Crypt (crypt) where

#include <unistd.h>

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Foreign (nullPtr)
import Foreign.C (CString)
import System.IO.Unsafe (unsafePerformIO)

import qualified Data.ByteString as BS

-- crypt is not re-entrable
lock :: MVar ()
lock = unsafePerformIO $ newMVar ()
{-# NOINLINE lock #-}

foreign import ccall unsafe "crypt"
   c_crypt :: CString -> CString -> IO CString

-- | Calls @crypt@.
crypt
    :: BS.ByteString  -- ^ key
    -> BS.ByteString  -- ^ salt
    -> Maybe BS.ByteString
crypt key salt = unsafePerformIO $ withMVar lock $ \_ ->
    BS.useAsCString key $ \ckey ->
    BS.useAsCString salt $ \csalt -> do
        res <- c_crypt ckey csalt
        if res == nullPtr
            then return Nothing
            else do
                bs <- BS.packCString res
                bs `seq` return (Just bs)
{-# NOINLINE crypt #-}
