module System.POSIX.Crypt (crypt) where

import qualified Data.ByteString as BS

-- | On windows systems this function always returns 'Nothing'.
crypt
    :: BS.ByteString  -- ^ key
    -> BS.ByteString  -- ^ salt
    -> Maybe BS.ByteString
crypt _ _ = Nothing
