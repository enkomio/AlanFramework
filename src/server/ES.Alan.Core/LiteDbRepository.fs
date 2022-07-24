namespace ES.Alan.Core

open System
open System.IO
open LiteDB
open System.Reflection
open System.Collections.Generic

type DbEntity<'T>(o: 'T) =
    new () = new DbEntity<'T>(Unchecked.defaultof<'T>)
    member val Id = String.Empty with get, set    
    member val Date = DateTime.Now with get, set
    member val Value = o with get, set
        
type LiteDbRepository<'T when 'T: not struct>() =  
    let _lock = new Object()

    let _typeStorageName =
        let typeOf = typeof<'T>
        if typeof<'T>.IsGenericType then
            typeOf.GenericTypeArguments
            |> Array.fold(fun (state: String) (elem: Type) ->
                state + "-" + elem.Name
            ) String.Empty
            |> fun v -> v.Substring(1)
        else
            typeOf.Name

    let _db = 
        let dataDirectory = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "data")
        Directory.CreateDirectory(dataDirectory) |> ignore
        let dbFile = Path.GetFullPath(Path.Combine(dataDirectory, _typeStorageName + ".db"))            
        let newDb = new LiteDatabase(dbFile) 
        newDb

    let getCollection() = 
        _db.GetCollection<DbEntity<'T>>("ALAN_" + _typeStorageName)
        
    member this.Get(id: String) = lock _lock (fun () ->
        let o = getCollection().FindById(new BsonValue(id))
        if box(o) <> null 
        then Some o.Value
        else None
    )

    member this.Upsert(dbEntity: DbEntity<'T>) = lock _lock (fun () ->
        let collection = getCollection()
        collection.Upsert(dbEntity) |> ignore
        collection.EnsureIndex(fun e -> e.Id) |> ignore   
        _db.Checkpoint()
    )
    
    member this.Delete(id: String) = lock _lock (fun () ->
        getCollection().Delete(new BsonValue(id)) |> ignore
        _db.Checkpoint()
    )

    member this.Query(predicate: 'T -> Boolean) = lock _lock (fun () ->
        getCollection().FindAll()
        |> Seq.filter(fun e -> predicate(e.Value))
        |> Seq.toArray
        |> Array.map(fun e -> e.Value)
    )

    member this.Count
        with get() = lock _lock (fun () ->
            getCollection().Count()
        )

    member this.Dispose() =
        _db.Dispose()

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()

