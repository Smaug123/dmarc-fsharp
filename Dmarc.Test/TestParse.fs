namespace Dmarc.Test

open System
open System.Net
open Dmarc
open NUnit.Framework
open System.Xml
open FsUnitTyped

[<TestFixture>]
module TestParse =
    let expectedDateRange =
        {
            Begin = DateTimeOffset (2024, 05, 26, 00, 00, 00, TimeSpan.Zero)
            End = DateTimeOffset (2024, 05, 26, 23, 59, 59, TimeSpan.Zero)
        }

    [<Test>]
    let ``Can parse DateRange`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let dateRangeNode =
            doc.["feedback"].FirstChild.ChildNodes
            |> Seq.cast<XmlNode>
            |> Seq.filter (fun i -> i.Name = "date_range")
            |> Seq.exactlyOne

        let actual =
            if isNull dateRangeNode then
                failwith "no version found"
            else
                DateRange.ofXml dateRangeNode

        actual |> shouldEqual expectedDateRange

    let expectedReportMetadata =
        {
            OrgName = Some "google.com"
            Email = "noreply-dmarc-support@google.com"
            ExtraContactInfo = Some (Uri "https://support.google.com/a/answer/2466580")
            ReportId = "12345678901234567890"
            DateRange = expectedDateRange
            Error = []
        }

    [<Test>]
    let ``Can parse ReportMetadata`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let reportMetadataNode = doc.["feedback"].FirstChild

        let actual =
            if isNull reportMetadataNode then
                failwith "no report metadata node found"
            else
                reportMetadataNode.Name |> shouldEqual "report_metadata"
                ReportMetadata.ofXml reportMetadataNode

        actual |> shouldEqual expectedReportMetadata

    let expectedPolicyPublished =
        {
            Domain = "example.com"
            DkimAlignment = Some Alignment.Relaxed
            SpfAlignment = Some Alignment.Relaxed
            Policy = Disposition.None
            SubdomainPolicy = Some Disposition.None
            Percentage = 100
            FailureOptions = None
        }

    [<Test>]
    let ``Can parse PolicyPublished`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let policyPublishedNode = doc.["feedback"].ChildNodes.[1]

        let actual =
            if isNull policyPublishedNode then
                failwith "no policy published node found"
            else
                policyPublishedNode.Name |> shouldEqual "policy_published"
                PolicyPublished.ofXml policyPublishedNode

        actual |> shouldEqual expectedPolicyPublished

    let expectedPolicyEvaluated : PolicyEvaluated =
        {
            Disposition = Disposition.None
            Dkim = DmarcResult.Pass
            Spf = DmarcResult.Pass
            Reason = []
        }

    [<Test>]
    let ``Can parse PolicyEvaluated`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let policyEvaluatedNode = doc.["feedback"].ChildNodes.[2].FirstChild.LastChild

        let actual =
            if isNull policyEvaluatedNode then
                failwith "no policy evaluated node found"
            else
                policyEvaluatedNode.Name |> shouldEqual "policy_evaluated"
                PolicyEvaluated.ofXml policyEvaluatedNode

        actual |> shouldEqual expectedPolicyEvaluated

    let expectedRow : Row =
        {
            SourceIp = IPAddress.Parse "192.168.0.1"
            Count = 1
            Policy = expectedPolicyEvaluated

        }

    [<Test>]
    let ``Can parse Row`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let rowNode = doc.["feedback"].ChildNodes.[2].FirstChild

        let actual =
            if isNull rowNode then
                failwith "no row node found"
            else
                rowNode.Name |> shouldEqual "row"
                Row.ofXml rowNode

        actual |> shouldEqual expectedRow

    let expectedIdentifier =
        {
            EnvelopeTo = None
            EnvelopeFrom = None
            HeaderFrom = "example.com"
        }

    [<Test>]
    let ``Can parse Identifiers`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let idNode = doc.["feedback"].ChildNodes.[2].ChildNodes.[1]

        let actual =
            if isNull idNode then
                failwith "no identifiers node found"
            else
                idNode.Name |> shouldEqual "identifiers"
                Identifier.ofXml idNode

        actual |> shouldEqual expectedIdentifier

    let expectedDkim : DkimAuthResult =
        {
            Domain = "example.com"
            Result = DkimResult.Pass
            Selector = Some "mySelector"
            HumanResult = None
        }

    [<Test>]
    let ``Can parse DKIM`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let node = doc.["feedback"].ChildNodes.[2].LastChild.FirstChild

        let actual =
            if isNull node then
                failwith "no dkim node found"
            else
                node.Name |> shouldEqual "dkim"
                DkimAuthResult.ofXml node

        actual |> shouldEqual expectedDkim

    let expectedSpf : SpfAuthResult =
        {
            Domain = "example.com"
            Scope = None
            Result = SpfResult.Pass
        }

    [<Test>]
    let ``Can parse SPF`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let node = doc.["feedback"].ChildNodes.[2].LastChild.LastChild

        let actual =
            if isNull node then
                failwith "no spf node found"
            else
                node.Name |> shouldEqual "spf"
                SpfAuthResult.ofXml node

        actual |> shouldEqual expectedSpf

    let expectedAuthResults =
        {
            Dkim = [ expectedDkim ]
            SpfHead = expectedSpf
            SpfTail = []
        }

    [<Test>]
    let ``Can parse auth results`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let node = doc.["feedback"].LastChild.LastChild

        let actual =
            if isNull node then
                failwith "no spf node found"
            else
                node.Name |> shouldEqual "auth_results"
                AuthResult.ofXml node

        actual |> shouldEqual expectedAuthResults

    let expectedRecord : Record =
        {
            Row = expectedRow
            Identifiers = expectedIdentifier
            AuthResults = expectedAuthResults
        }

    [<Test>]
    let ``Can parse record`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let node = doc.["feedback"].LastChild

        let actual =
            if isNull node then
                failwith "no spf node found"
            else
                node.Name |> shouldEqual "record"
                Record.ofXml node

        actual |> shouldEqual expectedRecord

    let expectedFeedback =
        {
            Version = None
            ReportMetadata = expectedReportMetadata
            PolicyPublished = expectedPolicyPublished
            Records = [ expectedRecord ]
        }

    [<Test>]
    let ``Can parse feedback`` () =
        use example = EmbeddedResource.read "example.xml"
        let doc = XmlDocument ()
        doc.Load example

        let node = doc.["feedback"]

        let actual =
            if isNull node then
                failwith "no feedback node found"
            else
                node.Name |> shouldEqual "feedback"
                Feedback.ofXml node

        actual |> shouldEqual expectedFeedback
