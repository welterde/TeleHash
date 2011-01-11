{-# language PackageImports #-}

module Telehash where

import Control.Concurrent.STM
import Control.Monad

import Data.Bits
import Data.List
import Data.Map
import qualified Data.ByteString.Char8 as B

import Network.Socket hiding (recv, recvFrom, send, sendTo)
import "network" Network.Socket.ByteString (recvFrom, sendTo)
import Network.BSD

import Text.JSON.AttoJSON as J

import Data.Digest.Pure.SHA

data Endpoint = Endpoint String Int

instance Show Endpoint where
    show (Endpoint ipAddr port) = ipAddr ++ ":" ++ (show port)

data RecvMsg = RecvMsg JSValue Int SockAddr

data TelexKey = To | Ring | Line | BytesReceived | Hop | Header String
              | See | Tap | Command String
              | End | Pop | Self | Sig | Href | From | Etag | Cht | Signal String
              | Telex String

data SwitchStatus = Offline | Booting | Online

data LineInfo = LineInfo {
    
    lnEndP          :: Endpoint,
    lnEndH          :: Digest,
    lnBytesReceived :: Int,
    lnRingIn        :: Int,
    lnRingOut       :: Int
    
}

data SwitchInfo = SwitchInfo {
    
    swStat  :: SwitchStatus,
    swLines :: Map Endpoint LineInfo
    
}

instance Show TelexKey where
    show To = "_to"
    show Ring = "_ring"
    show Line = "_line"
    show BytesReceived = "_br"
    show Hop = "_hop"
    show (Header header) = "." ++ header
    
    show See = ".see"
    show Tap = ".tap"
    show (Command command) = "." ++ command
    
    show End = "+end"
    show Pop = "+pop"
    show Self = "+self"
    show Sig = "+sig"
    show Href = "+href"
    show From = "+from"
    show Etag = "+etag"
    show Cht = "+cht"
    show (Signal signal) = "+" ++ signal
    
    show (Telex key) = key

bshow = B.pack . show

telexGet :: JSON a => TelexKey -> JSValue -> Maybe a
telexGet key telex = J.lookup (bshow key) telex

telexWith :: JSON a => TelexKey -> a -> JSValue -> JSValue
telexWith key value telex = J.updateField (bshow key) value telex

quickSockAddr:: String -> Int -> IO SockAddr
quickSockAddr hostName port = liftM addrAddress $ quickAddrInfo hostName port

quickAddrInfo :: String -> Int -> IO AddrInfo
quickAddrInfo hostName port = do
    addrinfos <- getAddrInfo 
                    (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
                    Nothing (Just $ show port)
    return $ head addrinfos

-- Bind to a listening socket.
bindServer :: Endpoint -> IO Socket
bindServer (Endpoint hostName port) = do
    
    serveraddr <- quickAddrInfo hostName port
    
    sock <- socket (addrFamily serveraddr) Datagram defaultProtocol
    
    -- Bind it to the address we're listening to
    bindSocket sock (addrAddress serveraddr)
    
    return sock

-- Listen for incoming messages.
-- Dispatch those messages to the channel.
fetchMessage :: TChan RecvMsg -> Socket -> IO () 
fetchMessage msgChan sock = do
    (msgRaw, addr) <- recvFrom sock 1024
    let msg = readJSON msgRaw
    case readJSON msgRaw of
        Just msg ->
            atomically $ writeTChan msgChan $ 
                RecvMsg msg (B.length msgRaw) addr
        Nothing ->
            return ()
    
sendMessage :: Socket -> String -> Int -> B.ByteString -> IO ()
sendMessage socket hostName port msg = do
    hostAddr <- quickSockAddr hostName port
    
    bytesSent <- sendTo socket msg hostAddr
    
    putStrLn $ "SEND[" ++ (show hostAddr) 
        ++ "][" ++ (show bytesSent) ++ "] " ++ (show msg)
    
    return ()

--reactor :: TChan RecvMsg -> Socket -> IO ()
--    (RecvMsg msg msgLen sockAddr) <- atomically $ readTChan logChan

-----------------------------------------------------------------------------
                          -- Telehash switch design --
-----------------------------------------------------------------------------
-- Use STM in a message-passing style. Listener thread will decode telex and
-- send to a reactor-dispatch process. This process will keep track of 
-- switch and line state in TVars.
--
-- I'm really new to Haskell but I'm thinking an application on top of the 
-- switch will need to "register" with the STM in such a way as to receive 
-- messages based on pattern matching
--
-----------------------------------------------------------------------------


