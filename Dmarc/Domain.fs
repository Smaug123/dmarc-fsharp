namespace Dmarc

open System
open System.Net
open System.Xml

type DateRange =
    {
        Begin : DateTimeOffset
        End : DateTimeOffset
    }

    static member ofXml (node : XmlNode) : DateRange =
        if node.ChildNodes.Count <> 2 then
            failwith $"expected exactly two nodes in DateRange, got %i{node.ChildNodes.Count}: %s{node.InnerXml}"

        let beginContents, endContents =
            match node.FirstChild, node.LastChild with
            | OneChildNode "begin" (NoChildrenNode (Int64 beginNode)),
              OneChildNode "end" (NoChildrenNode (Int64 endNode))
            | OneChildNode "end" (NoChildrenNode (Int64 endNode)),
              OneChildNode "begin" (NoChildrenNode (Int64 beginNode)) -> beginNode, endNode
            | c1, c2 -> failwith $"Expected a begin and an end node in DateRange, got %s{c1.Name} and %s{c2.Name}"

        {
            Begin = DateTimeOffset.FromUnixTimeSeconds beginContents
            End = DateTimeOffset.FromUnixTimeSeconds endContents
        }

type ReportMetadata =
    {
        OrgName : string option
        Email : string
        ExtraContactInfo : Uri
        ReportId : string
        DateRange : DateRange
        Error : string list
    }

    static member ofXml (node : XmlNode) : ReportMetadata =
        if not node.HasChildNodes then
            failwith "expected report_metadata node to have children, but it did not"

        let mutable orgName = None
        let mutable email = None
        let mutable extraContactInfo = None
        let mutable reportId = None
        let mutable dateRange = None
        let mutable errors = ResizeArray ()

        for i in node.ChildNodes do
            match i with
            | OneChildNode "org_name" (NoChildrenNode v) ->
                match orgName with
                | None -> orgName <- Some v
                | Some v2 -> failwith $"Duplicate values for org_name, %s{v2} and %s{v}"
            | OneChildNode "email" (NoChildrenNode v) ->
                match email with
                | None -> email <- Some v
                | Some v2 -> failwith $"Duplicate values for email, %s{v2} and %s{v}"
            | OneChildNode "report_id" (NoChildrenNode v) ->
                match reportId with
                | None -> reportId <- Some v
                | Some v2 -> failwith $"Duplicate values for reportId, %s{v2} and %s{v}"
            | OneChildNode "extra_contact_info" (NoChildrenNode v) ->
                match extraContactInfo with
                | None -> extraContactInfo <- Some (Uri v)
                | Some v2 -> failwith $"Duplicate values for extra_contact_info, %O{v2} and %s{v}"
            | NodeWithChildren "date_range" ->
                match dateRange with
                | None -> dateRange <- Some (DateRange.ofXml i)
                | Some v2 -> failwith $"Duplicate values for date_range, %O{v2} and %s{i.InnerText}"
            | OneChildNode "error" (NoChildrenNode v) -> errors.Add v
            | _ -> failwith $"Unrecognised node %s{i.Name}: %s{i.InnerText}"

        let email =
            email |> Option.defaultWith (fun () -> failwith "expected email, got none")

        let reportId =
            reportId
            |> Option.defaultWith (fun () -> failwith "expected report_id, got none")

        let extraContactInfo =
            extraContactInfo
            |> Option.defaultWith (fun () -> failwith "expected extra_contact_info, got none")

        let dateRange =
            dateRange
            |> Option.defaultWith (fun () -> failwith "expected date_range, got none")

        {
            Error = errors |> Seq.toList
            OrgName = orgName
            Email = email
            ExtraContactInfo = extraContactInfo
            ReportId = reportId
            DateRange = dateRange
        }

type Alignment =
    | Relaxed
    | Strict

    static member ofString (s : string) : Alignment =
        match s with
        | "r" -> Alignment.Relaxed
        | "s" -> Alignment.Strict
        | _ -> failwith $"Didn't recognise alignment %s{s}"

[<RequireQualifiedAccess>]
type Disposition =
    | None
    | Quarantine
    | Reject

    static member ofString (s : string) : Disposition =
        match s with
        | "none" -> Disposition.None
        | "quarantine" -> Disposition.Quarantine
        | "reject" -> Disposition.Reject
        | _ -> failwith $"Didn't recognise disposition %s{s}"

type PolicyPublished =
    {
        Domain : string
        DkimAlignment : Alignment option
        SpfAlignment : Alignment option
        Policy : Disposition
        SubdomainPolicy : Disposition
        Percentage : int
        /// Mandated by RFC-7489 but absent from Google's response.
        FailureOptions : string option
    }

    static member ofXml (node : XmlNode) : PolicyPublished =
        if not node.HasChildNodes then
            failwith "expected policy_published node to have children, but it did not"

        let mutable domain = None
        let mutable dkimAlignment = None
        let mutable spfAlignment = None
        let mutable policy = None
        let mutable subdomainPolicy = None
        let mutable percentage = None
        let mutable failureOptions = None

        for i in node.ChildNodes do
            match i with
            | OneChildNode "domain" (NoChildrenNode v) ->
                match domain with
                | None -> domain <- Some v
                | Some v2 -> failwith $"domain appeared twice, values %s{v2} and %s{v}"
            | OneChildNode "adkim" (NoChildrenNode v) ->
                match dkimAlignment with
                | None -> dkimAlignment <- Some (Alignment.ofString v)
                | Some v2 -> failwith $"dkimAlignment appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "aspf" (NoChildrenNode v) ->
                match spfAlignment with
                | None -> spfAlignment <- Some (Alignment.ofString v)
                | Some v2 -> failwith $"spfAlignment appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "p" (NoChildrenNode v) ->
                match policy with
                | None -> policy <- Some (Disposition.ofString v)
                | Some v2 -> failwith $"policy appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "sp" (NoChildrenNode v) ->
                match subdomainPolicy with
                | None -> subdomainPolicy <- Some (Disposition.ofString v)
                | Some v2 -> failwith $"subdomain policy appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "pct" (NoChildrenNode (Int v)) ->
                match percentage with
                | None -> percentage <- Some v
                | Some v2 -> failwith $"percentage appeared twice, values %i{v2} and %i{v}"
            | OneChildNode "fo" (NoChildrenNode v) ->
                match failureOptions with
                | None -> failureOptions <- Some v
                | Some v2 -> failwith $"failure options appeared twice, values %s{v2} and %s{v}"
            | OneChildNode "np" (NoChildrenNode _) ->
                // RFC-7489 doesn't mention this but Google returns it
                ()
            | _ -> failwith $"Unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let domain =
            domain |> Option.defaultWith (fun () -> failwith "expected domain, got none")

        let policy =
            policy |> Option.defaultWith (fun () -> failwith "expected policy, got none")

        let subdomainPolicy =
            subdomainPolicy
            |> Option.defaultWith (fun () -> failwith "expected subdomainPolicy, got none")

        let percentage =
            percentage
            |> Option.defaultWith (fun () -> failwith "expected percentage, got none")

        {
            Domain = domain
            DkimAlignment = dkimAlignment
            SpfAlignment = spfAlignment
            Policy = policy
            SubdomainPolicy = subdomainPolicy
            Percentage = percentage
            FailureOptions = failureOptions
        }

type DmarcResult =
    | Pass
    | Fail

    static member ofString (s : string) : DmarcResult =
        match s with
        | "pass" -> DmarcResult.Pass
        | "fail" -> DmarcResult.Fail
        | _ -> failwith $"Unrecognised DMARC result: %s{s}"

type PolicyOverride =
    | Forwarded
    | SampledOut
    | TrustedForwarder
    | MailingList
    | LocalPolicy
    | Other

    static member ofString (s : string) : PolicyOverride =
        match s with
        | "forwarded" -> PolicyOverride.Forwarded
        | "sampled_out" -> PolicyOverride.SampledOut
        | "trusted_forwarder" -> PolicyOverride.TrustedForwarder
        | "mailing_list" -> PolicyOverride.MailingList
        | "local_policy" -> PolicyOverride.LocalPolicy
        | "other" -> PolicyOverride.Other
        | _ -> failwith $"unrecognised policy override: %s{s}"

type PolicyOverrideReason =
    {
        Type : PolicyOverride
        Comment : string option
    }

    static member ofXml (node : XmlNode) : PolicyOverrideReason =
        if not node.HasChildNodes then
            failwith "expected policy override reason node to have children, but it did not"

        let mutable ty = None
        let mutable comment = None

        for i in node.ChildNodes do
            match i with
            | OneChildNode "type" (NoChildrenNode v) ->
                match ty with
                | None -> ty <- Some (PolicyOverride.ofString v)
                | Some v2 -> failwith $"type appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "comment" (NoChildrenNode v) ->
                match comment with
                | None -> comment <- Some v
                | Some v2 -> failwith $"comment appeared twice, values %s{v2} and %s{v}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let ty =
            ty
            |> Option.defaultWith (fun () -> failwith "expected policy override, got none")

        {
            Type = ty
            Comment = comment
        }

type PolicyEvaluated =
    {
        Disposition : Disposition
        Dkim : DmarcResult
        Spf : DmarcResult
        Reason : PolicyOverrideReason list
    }

    static member ofXml (node : XmlNode) : PolicyEvaluated =
        if not node.HasChildNodes then
            failwith "expected policy evaluation node to have children, but it did not"

        let mutable disp = None
        let mutable dkim = None
        let mutable spf = None
        let reason = ResizeArray ()

        for i in node.ChildNodes do
            match i with
            | OneChildNode "disposition" (NoChildrenNode v) ->
                match disp with
                | None -> disp <- Some (Disposition.ofString v)
                | Some v2 -> failwith $"disposition appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "dkim" (NoChildrenNode v) ->
                match dkim with
                | None -> dkim <- Some (DmarcResult.ofString v)
                | Some v2 -> failwith $"dkim appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "spf" (NoChildrenNode v) ->
                match spf with
                | None -> spf <- Some (DmarcResult.ofString v)
                | Some v2 -> failwith $"spf appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "reason" v -> reason.Add (PolicyOverrideReason.ofXml v)
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let spf = spf |> Option.defaultWith (fun () -> failwith "expected spf, got none")
        let dkim = dkim |> Option.defaultWith (fun () -> failwith "expected dkim, got none")

        let disp =
            disp |> Option.defaultWith (fun () -> failwith "expected disposition, got none")

        {
            Disposition = disp
            Dkim = dkim
            Spf = spf
            Reason = reason |> Seq.toList
        }

type Row =
    {
        SourceIp : IPAddress
        Count : int
        Policy : PolicyEvaluated
    }

    static member ofXml (node : XmlNode) : Row =
        if not node.HasChildNodes then
            failwith "expected policy evaluation node to have children, but it did not"

        let mutable source = None
        let mutable count = None
        let mutable policy = None

        for i in node.ChildNodes do
            match i with
            | OneChildNode "source_ip" (NoChildrenNode v) ->
                match source with
                | None -> source <- Some (IPAddress.Parse v)
                | Some v2 -> failwith $"source appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "count" (NoChildrenNode (Int v)) ->
                match count with
                | None -> count <- Some v
                | Some v2 -> failwith $"count appeared twice, values %i{v2} and %i{v}"
            | NodeWithChildren "policy_evaluated" ->
                match policy with
                | None -> policy <- Some (PolicyEvaluated.ofXml i)
                | Some v2 -> failwith $"policy_evaluated appeared twice, values %O{v2} and %s{i.InnerText}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let source =
            source |> Option.defaultWith (fun () -> failwith "expected source, got none")

        let count =
            count |> Option.defaultWith (fun () -> failwith "expected count, got none")

        let policy =
            policy
            |> Option.defaultWith (fun () -> failwith "expected policy_evaluated, got none")

        {
            SourceIp = source
            Count = count
            Policy = policy
        }

type Identifier =
    {
        EnvelopeTo : string option
        /// According to the RFC, this is required, but Google doesn't return it
        EnvelopeFrom : string option
        HeaderFrom : string
    }

    static member ofXml (node : XmlNode) : Identifier =
        if not node.HasChildNodes then
            failwith "expected identifiers node to have children, but it did not"

        let mutable envelopeTo = None
        let mutable envelopeFrom = None
        let mutable headerFrom = None

        for i in node.ChildNodes do
            match i with
            | OneChildNode "header_from" (NoChildrenNode v) ->
                match headerFrom with
                | None -> headerFrom <- Some v
                | Some v2 -> failwith $"header_from appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "envelope_to" (NoChildrenNode v) ->
                match envelopeTo with
                | None -> envelopeTo <- Some v
                | Some v2 -> failwith $"envelope_to appeared twice, values %s{v2} and %s{v}"
            | OneChildNode "envelope_from" (NoChildrenNode v) ->
                match envelopeFrom with
                | None -> envelopeFrom <- Some v
                | Some v2 -> failwith $"envelope_from appeared twice, values %O{v2} and %s{v}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let headerFrom =
            headerFrom
            |> Option.defaultWith (fun () -> failwith "expected header_from, got none")

        {
            HeaderFrom = headerFrom
            EnvelopeFrom = envelopeFrom
            EnvelopeTo = envelopeTo
        }

[<RequireQualifiedAccess>]
type DkimResult =
    | None
    | Pass
    | Fail
    | Policy
    | Neutral
    | TempError
    | PermError

    static member ofString (s : string) : DkimResult =
        match s with
        | "none" -> DkimResult.None
        | "pass" -> DkimResult.Pass
        | "fail" -> DkimResult.Fail
        | "policy" -> DkimResult.Policy
        | "neutral" -> DkimResult.Neutral
        | "temperror" -> DkimResult.TempError
        | "permerror" -> DkimResult.PermError
        | _ -> failwith $"Unrecognised DKIM result: %s{s}"

type DkimAuthResult =
    {
        Domain : string
        Selector : string option
        Result : DkimResult
        HumanResult : string option
    }

    static member ofXml (node : XmlNode) : DkimAuthResult =
        if not node.HasChildNodes then
            failwith "expected dkim auth result node to have children, but it did not"

        let mutable domain = None
        let mutable selector = None
        let mutable result = None
        let mutable humanResult = None

        for i in node.ChildNodes do
            match i with
            | OneChildNode "domain" (NoChildrenNode v) ->
                match domain with
                | None -> domain <- Some v
                | Some v2 -> failwith $"domain appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "selector" (NoChildrenNode v) ->
                match selector with
                | None -> selector <- Some v
                | Some v2 -> failwith $"selctor appeared twice, values %s{v2} and %s{v}"
            | OneChildNode "result" (NoChildrenNode v) ->
                match result with
                | None -> result <- Some (DkimResult.ofString v)
                | Some v2 -> failwith $"result appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "human_result" (NoChildrenNode v) ->
                match humanResult with
                | None -> humanResult <- Some v
                | Some v2 -> failwith $"human_result appeared twice, values %s{v2} and %s{v}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let domain =
            domain |> Option.defaultWith (fun () -> failwith "expected domain, got none")

        let result =
            result |> Option.defaultWith (fun () -> failwith "expected result, got none")

        {
            Domain = domain
            Selector = selector
            Result = result
            HumanResult = humanResult
        }

type SpfDomainScope =
    | Helo
    | Mfrom

    static member ofString (s : string) : SpfDomainScope =
        match s with
        | "helo" -> SpfDomainScope.Helo
        | "mfrom" -> SpfDomainScope.Mfrom
        | _ -> failwith $"Unrecognised SPF domain scope: %s{s}"

[<RequireQualifiedAccess>]
type SpfResult =
    | None
    | Neutral
    | Pass
    | Fail
    | SoftFail
    | TempError
    | PermError

    static member ofString (s : string) : SpfResult =
        match s with
        | "none" -> SpfResult.None
        | "neutral" -> SpfResult.Neutral
        | "pass" -> SpfResult.Pass
        | "fail" -> SpfResult.Fail
        | "softfail" -> SpfResult.SoftFail
        | "unknown"
        | "temperror" -> SpfResult.TempError
        | "error"
        | "permerror" -> SpfResult.PermError
        | _ -> failwith $"Unrecognised SPF result: %s{s}"

type SpfAuthResult =
    {
        Domain : string
        /// Mandatory according to the RFC, but not supplied by Google
        Scope : SpfDomainScope option
        Result : SpfResult
    }

    static member ofXml (node : XmlNode) : SpfAuthResult =
        if not node.HasChildNodes then
            failwith "expected spf auth result to have children, but it did not"

        let mutable domain = None
        let mutable scope = None
        let mutable result = None

        for i in node.ChildNodes do
            match i with
            | OneChildNode "domain" (NoChildrenNode v) ->
                match domain with
                | None -> domain <- Some v
                | Some v2 -> failwith $"domain appeared twice, values %s{v2} and %s{v}"
            | OneChildNode "result" (NoChildrenNode v) ->
                match result with
                | None -> result <- Some (SpfResult.ofString v)
                | Some v2 -> failwith $"result appeared twice, values %O{v2} and %s{v}"
            | OneChildNode "scope" (NoChildrenNode v) ->
                match scope with
                | None -> scope <- Some (SpfDomainScope.ofString v)
                | Some v2 -> failwith $"human_result appeared twice, values %O{v2} and %s{v}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let domain =
            domain |> Option.defaultWith (fun () -> failwith "expected domain, got none")

        let result =
            result |> Option.defaultWith (fun () -> failwith "expected result, got none")

        {
            Domain = domain
            Scope = scope
            Result = result
        }

type AuthResult =
    {
        Dkim : DkimAuthResult list
        SpfHead : SpfAuthResult
        SpfTail : SpfAuthResult list
    }

    static member ofXml (node : XmlNode) : AuthResult =
        if not node.HasChildNodes then
            failwith "expected auth result to have children, but it did not"

        let dkim = ResizeArray ()
        let mutable spfHead = None
        let spfTail = ResizeArray ()

        for i in node.ChildNodes do
            match i with
            | NodeWithChildren "dkim" -> dkim.Add (DkimAuthResult.ofXml i)
            | NodeWithChildren "spf" ->
                let v = SpfAuthResult.ofXml i

                match spfHead with
                | None -> spfHead <- Some v
                | Some _ -> spfTail.Add v
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let spfHead =
            spfHead
            |> Option.defaultWith (fun () -> failwith "expected spf to have at least one element, got none")

        {
            Dkim = dkim |> Seq.toList
            SpfHead = spfHead
            SpfTail = spfTail |> Seq.toList
        }

type Record =
    {
        Row : Row
        Identifiers : Identifier
        AuthResults : AuthResult
    }

    static member ofXml (node : XmlNode) : Record =
        if not node.HasChildNodes then
            failwith "expected record result to have children, but it did not"

        let mutable row = None
        let mutable identifiers = None
        let mutable authResult = None

        for i in node.ChildNodes do
            match i with
            | NodeWithChildren "auth_results" ->
                match authResult with
                | None -> authResult <- Some (AuthResult.ofXml i)
                | Some v2 -> failwith $"auth_results appeared twice, values %O{v2} and %s{i.InnerText}"
            | NodeWithChildren "row" ->
                match row with
                | None -> row <- Some (Row.ofXml i)
                | Some v2 -> failwith $"row appeared twice, values %O{v2} and %s{i.InnerText}"
            | NodeWithChildren "identifiers" ->
                match identifiers with
                | None -> identifiers <- Some (Identifier.ofXml i)
                | Some v2 -> failwith $"identifiers appeared twice, values %O{v2} and %s{i.InnerText}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let row = row |> Option.defaultWith (fun () -> failwith "expected row, got none")

        let identifiers =
            identifiers
            |> Option.defaultWith (fun () -> failwith "expected identifiers, got none")

        let authResult =
            authResult
            |> Option.defaultWith (fun () -> failwith "expected auth_results, got none")

        {
            Row = row
            Identifiers = identifiers
            AuthResults = authResult
        }

type Feedback =
    {
        /// strictly speaking a decimal; also mandatory according to the RFC but not
        /// supplied by Google
        Version : string option
        ReportMetadata : ReportMetadata
        PolicyPublished : PolicyPublished
        Records : Record list
    }

    static member ofXml (node : XmlNode) : Feedback =
        if not node.HasChildNodes then
            failwith "expected record result to have children, but it did not"

        let mutable version = None
        let mutable reportMetadata = None
        let mutable policyPublished = None
        let records = ResizeArray ()

        for i in node.ChildNodes do
            match i with
            | NodeWithChildren "record" -> records.Add (Record.ofXml i)
            | NodeWithChildren "policy_published" ->
                match policyPublished with
                | None -> policyPublished <- Some (PolicyPublished.ofXml i)
                | Some v2 -> failwith $"policy_published appeared twice, values %O{v2} and %s{i.InnerText}"
            | NodeWithChildren "report_metadata" ->
                match reportMetadata with
                | None -> reportMetadata <- Some (ReportMetadata.ofXml i)
                | Some v2 -> failwith $"report_metadata appeared twice, values %O{v2} and %s{i.InnerText}"
            | OneChildNode "version" (NoChildrenNode v) ->
                match version with
                | None -> version <- Some v
                | Some v2 -> failwith $"version appeared twice, values %O{v2} and %s{v}"
            | _ -> failwith $"unrecognised node: %s{i.Name}, %s{i.InnerText}"

        let policyPublished =
            policyPublished
            |> Option.defaultWith (fun () -> failwith "expected policy_published, got none")

        let reportMetadata =
            reportMetadata
            |> Option.defaultWith (fun () -> failwith "expected report_metadata, got none")

        {
            Records = records |> Seq.toList
            PolicyPublished = policyPublished
            ReportMetadata = reportMetadata
            Version = version
        }
