namespace ES.Alan.Core

open System
open Newtonsoft.Json.Linq

module JsonHelper =
    let get(j: Object, name: String) =            
        let mutable p = Some(j :?> JToken)
        name.Split('.')
        |> Array.iter(fun n ->
            p <-
                match p with
                | Some pp -> 
                    let tmp = pp.[n]
                    if tmp <> null then Some tmp else None
                | None -> None
        )
        p
    
    let getArray(j: Object, name: String) =   
        match get(j, name) with
        | Some v -> v.Children() |> Seq.toArray
        | None -> Array.empty<JToken>        

