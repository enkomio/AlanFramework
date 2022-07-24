namespace ES.Alan.Core

open System
open ES.Alan.Core.Entities

type IListener = 
    abstract GetListenerType: unit -> ListenerType
    abstract Start: unit -> unit
    abstract Address: String with get
    abstract Port: Int32 with get
