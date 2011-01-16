
module Main where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad

import qualified Data.ByteString.Char8 as B

import Network.Socket (Socket)

import Telehash

printRecvMsg logChan = do
    (RecvMsg msg msgLen sockAddr) <- atomically $ readTChan logChan
    putStrLn $ "RECV FROM[" ++ (show sockAddr) 
        ++ "][" ++ (show msgLen) ++ "] " ++ (show msg)
    
    putStrLn $ "_to = " ++ 
        case telexGet "_to" msg of
            (Just to) -> to
            Nothing -> "[undefined]"

main = do
    msgChan <- newTChanIO
    logChan <- atomically $ dupTChan msgChan
    
    serverSocket <- bindServer $ Endpoint "0.0.0.0" 42425
    
    forkIO $ forever $ fetchMessage msgChan serverSocket
    
    forkIO $ forever $ printRecvMsg logChan
    
    startSwitch msgChan serverSocket
    
