namespace Dmarc.Test

open System.IO
open System.Reflection

[<RequireQualifiedAccess>]
module EmbeddedResource =
    let read (fileName : string) : Stream =
        let assy = Assembly.GetExecutingAssembly ()
        let fileName = $"%s{assy.GetName().Name}.%s{fileName}"
        let s = assy.GetManifestResourceStream fileName

        if isNull s then
            let names = assy.GetManifestResourceNames () |> String.concat "\n"
            failwith $"Could not find resource %s{fileName}. Available:\n%s{names}"

        s
