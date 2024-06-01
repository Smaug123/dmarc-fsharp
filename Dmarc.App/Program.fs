namespace Dmarc.App

open System.IO
open System.Xml
open Dmarc

module Program =
    [<EntryPoint>]
    let main argv =
        let file =
            match argv with
            | [| file |] -> file
            | _ -> failwith "Call with exactly one arg, the XML file to parse"

        use s = File.OpenRead file
        let doc = XmlDocument ()
        doc.Load s

        let feedback = Feedback.ofXml doc.["feedback"]
        0
