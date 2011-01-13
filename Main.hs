
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
        case telexGet To msg of
            (Just to) -> to
            Nothing -> "[undefined]"

main = do
    msgChan <- newTChanIO
    logChan <- atomically $ dupTChan msgChan
    
    serverSocket <- bindServer $ Endpoint "0.0.0.0" 42425
    
    forkIO $ forever $ fetchMessage msgChan serverSocket
    
    sendMessage serverSocket "127.0.0.1" 42424
        (B.pack 
            "{'+end':'24fc702463e195f3c94aaa5e33a806955fab3b36', '_to':'208.68.163.247:42424'}")
    
    startSwitch msgChan serverSocket
    
    forever $ printRecvMsg logChan
    
