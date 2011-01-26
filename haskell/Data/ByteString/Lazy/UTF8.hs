{-# language PackageImports, TypeSynonymInstances #-}

module Data.ByteString.Lazy.UTF8 where

import "bytestring" Data.ByteString.Lazy(ByteString)
import qualified "bytestring" Data.ByteString.Lazy as BS

import Codec.Binary.UTF8.String(encode)

-- | Converts a Haskell string into a UTF8 encoded bytestring.
fromString :: String -> ByteString
fromString xs = BS.pack (encode xs)

