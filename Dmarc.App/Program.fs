namespace Dmarc.App

open System
open System.IO
open System.IO.Compression
open System.Security.Cryptography
open System.Text
open System.Threading
open System.Xml
open Dmarc
open MimeKit

module Program =
    let emptyDisposable () =
        { new System.IDisposable with
            member _.Dispose () = ()
        }

    let loadXmlFromBase64Gzip (s : string) : XmlDocument =
        let doc = XmlDocument ()

        let bytes = Encoding.UTF8.GetBytes s
        use reader = new MemoryStream (bytes)
        use b64Transform = new FromBase64Transform ()
        use b64Stream = new CryptoStream (reader, b64Transform, CryptoStreamMode.Read)
        use gz = new GZipStream (b64Stream, CompressionMode.Decompress)

        doc.Load gz
        doc

    let loadXmlFromGzip (s : Stream) : XmlDocument =
        let doc = XmlDocument ()
        use gz = new GZipStream (s, CompressionMode.Decompress, leaveOpen = true)

        doc.Load gz
        doc

    let loadXmlFromFile (file : FileInfo) : XmlDocument =
        let doc = XmlDocument ()
        use file = file.OpenRead ()
        doc.Load file
        doc

    [<EntryPoint>]
    let main argv =
        let dir, domain, email =
            match argv with
            | [| f ; domain ; email |] -> DirectoryInfo f, domain, email
            | _ -> failwith "give exactly three args, a mailbox folder, a domain, and a dmarc email address"

        let errors = ResizeArray ()

        let success =
            dir.EnumerateFileSystemInfos ()
            |> Seq.choose (fun entry ->
                if Directory.Exists entry.FullName then
                    failwith "Encountered a directory"

                let file = FileInfo entry.FullName

                let message = MimeMessage.Load file.FullName

                let isDmarc =
                    message.To
                    |> Seq.exists (fun i ->
                        match i with
                        | :? MailboxAddress as i -> i.Address = email
                        | _ ->
                            match message.Headers.["X-Original-To"] with
                            | null ->
                                errors.Add message
                                false
                            | m -> m = email
                    )

                if not isDmarc then
                    None
                else

                message.Attachments
                |> Seq.map (fun m ->
                    let contentsResult = new MemoryStream ()

                    let m =
                        match m with
                        | :? MimePart as m -> m
                        | _ -> failwithf "Not a MIME part: %+A" m

                    do
                        match m.ContentTransferEncoding with
                        | ContentEncoding.Base64 ->
                            use b64Transform = new FromBase64Transform ()

                            use b64Stream =
                                new CryptoStream (
                                    m.Content.Stream,
                                    b64Transform,
                                    CryptoStreamMode.Read,
                                    leaveOpen = true
                                )

                            b64Stream.CopyTo contentsResult
                        | e -> failwithf "Unrecognised content encoding: %O" e

                    contentsResult.Seek (0L, SeekOrigin.Begin) |> ignore<int64>

                    let senderIsMimecast =
                        message.From
                        |> Seq.map (fun addr ->
                            match addr with
                            | :? MailboxAddress as a ->
                                a.Domain.EndsWith (".mimecastreport.com", StringComparison.Ordinal)
                            | _ -> failwithf "unrecognised sender: %+A" addr
                        )
                        |> Seq.tryExactlyOne

                    let parent, stream =
                        match m.ContentType.MimeType, senderIsMimecast with
                        | "application/zip", _
                        // mimecast is a lying liar who lies about their content types...
                        | "application/gzip", Some true ->
                            let result =
                                try
                                    new ZipArchive (contentsResult, ZipArchiveMode.Read, leaveOpen = true) |> Ok
                                with :? InvalidDataException ->
                                    if senderIsMimecast = Some true then
                                        Error ()
                                    else
                                        reraise ()

                            match result with
                            | Ok result ->
                                let entry = Seq.exactlyOne result.Entries
                                result :> IDisposable, entry.Open ()
                            | Error () ->
                                // ... except when they don't lie
                                // oh my god mimecast why can't you just be normal
                                let s =
                                    new GZipStream (contentsResult, CompressionMode.Decompress, leaveOpen = true)

                                emptyDisposable (), s :> Stream
                        | "application/gzip", _ ->
                            let s =
                                new GZipStream (contentsResult, CompressionMode.Decompress, leaveOpen = true)

                            emptyDisposable (), s :> Stream
                        | s, _ -> failwith $"Unrecognised MIME type: %s{s}"

                    use parent = parent
                    use stream = stream

                    let doc = XmlDocument ()
                    doc.Load stream
                    doc
                )
                |> Seq.map (fun doc -> Feedback.ofXml doc.["feedback"])
                |> Seq.toList
                |> Some
            )
            |> Seq.concat
            |> Seq.toList

        if errors.Count <> 0 then
            failwith $"Got errors! %+A{errors}"

        let failures = ref 0
        let total = ref 0
        let tempErrors = ref 0

        for report in success do
            if not report.ReportMetadata.Error.IsEmpty then
                eprintfn $"Got an error report: %+A{report}"

            if report.PolicyPublished.Domain <> domain then
                eprintfn $"Got a report which was not for my domain: %+A{report}"

            for record in report.Records do
                let mutable isOk = true

                match record.Row.Policy.Disposition with
                | Disposition.Quarantine ->
                    isOk <- false
                    eprintfn $"Quarantine"
                | Disposition.Reject ->
                    isOk <- false
                    eprintfn $"Rejected"
                | Disposition.None -> ()

                match record.Row.Policy.Dkim with
                | DmarcResult.Fail ->
                    if
                        record.AuthResults.Dkim
                        |> List.forall (fun r -> r.Result = DkimResult.TempError)
                    then
                        eprintfn $"Temporary failure killed DKIM; not counting."
                        Interlocked.Increment tempErrors |> ignore<int>
                    else
                        isOk <- false
                        eprintfn $"Failed DKIM."
                | DmarcResult.Pass -> ()

                match record.Row.Policy.Spf with
                | DmarcResult.Fail ->
                    isOk <- false
                    eprintfn $"Failed SPF"
                | DmarcResult.Pass -> ()

                match record.AuthResults.SpfHead.Result with
                | SpfResult.Pass -> ()
                | _ ->
                    isOk <- false
                    eprintfn $"SPF auth result was not Pass"

                if not isOk then
                    Interlocked.Increment failures |> ignore<int>
                    eprintfn $"%O{record}"

                Interlocked.Increment total |> ignore<int>

        printfn "Failed: %i/%i" failures.Value total.Value
        0
