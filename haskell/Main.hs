
module Main where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad

import qualified Data.ByteString.Char8 as B

import Network.Socket (Socket)

import Telehash

main = do
    let config = SwitchConfig {
            swAddress = Endpoint "0.0.0.0" 42425,
            swBootstrap = Endpoint "127.0.0.1" 42424
        }

    swHandle <- startSwitch config
    interact id

