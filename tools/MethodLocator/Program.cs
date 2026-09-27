using Il2CppDumper;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: MethodLocator <libil2cpp.so> <repaired-metadata.dat>");
    return 2;
}

using var nativeStream = new MemoryStream(File.ReadAllBytes(args[0]));
using var metadataStream = new MemoryStream(File.ReadAllBytes(args[1]));
var metadata = new Metadata(metadataStream);
var native = new Elf64(nativeStream);
native.SetProperties(metadata.Version, metadata.metadataUsagesCount);
native.Init(0xbdf4fa0, 0xc315bd8);

foreach (var address in new ulong[] { 0xc5737d0, 0xc5737d8, 0xc5737e0, 0xc5737e8, 0xc530ea0 })
{
    try {
        var slot = native.MapVATR<ulong>(address);
        var encoded = native.MapVATR<ulong>(slot);
        Console.Error.WriteLine($"METADATA SLOT 0x{address:X}: ptr 0x{slot:X}, encoded 0x{encoded:X}");
    }
    catch (Exception ex) { Console.Error.WriteLine($"METADATA SLOT 0x{address:X}: {ex.Message}"); }
}
foreach (var index in new[] { 58, 53, 50 })
{
    var field = metadata.fieldRefs[index];
    var type = native.types[field.typeIndex];
    var typeDef = metadata.typeDefs[(int)type.datapoint];
    var fieldIndex = typeDef.fieldStart + field.fieldIndex;
    var fieldDef = metadata.fieldDefs[fieldIndex];
    var found = metadata.GetFieldDefaultValueFromIndex(fieldIndex, out var defaultValue);
    Console.Error.WriteLine($"FIELD REF {index}: typeIndex={field.typeIndex}, localFieldIndex={field.fieldIndex}, type={type.type}, datapoint=0x{type.datapoint:X}, typeName={metadata.GetStringFromIndex(typeDef.nameIndex)}, fieldName={metadata.GetStringFromIndex(fieldDef.nameIndex)}, fieldIndex={fieldIndex}, default={found} {defaultValue?.dataIndex}");
    if (found && defaultValue.dataIndex >= 0)
    {
        metadata.Position = metadata.GetDefaultValueFromIndex(defaultValue.dataIndex);
        Console.Error.WriteLine($"FIELD DATA {index}: {Convert.ToHexString(metadata.Reader.ReadBytes(48))}");
    }
}

var targets = new HashSet<string> { "App.Crypto.CryptProvider" };

Console.WriteLine("image\tnamespace\ttype\tmethod\tmethod_index\ttoken\tva\trva\tfile_offset");
foreach (var image in metadata.imageDefs)
{
    var imageName = metadata.GetStringFromIndex(image.nameIndex);
    for (var typeIndex = image.typeStart; typeIndex < image.typeStart + image.typeCount; typeIndex++)
    {
        var type = metadata.typeDefs[typeIndex];
        var namespaceName = metadata.GetStringFromIndex(type.namespaceIndex);
        var typeName = metadata.GetStringFromIndex(type.nameIndex);
        if (!targets.Contains(namespaceName + "." + typeName)) continue;
        for (var methodIndex = type.methodStart; methodIndex < type.methodStart + type.method_count; methodIndex++)
        {
            var method = metadata.methodDefs[methodIndex];
            var methodName = metadata.GetStringFromIndex(method.nameIndex);
            try
            {
                var pointer = native.GetMethodPointer(imageName, method);
                var offset = pointer == 0 ? 0 : native.MapVATR(pointer);
                Console.WriteLine($"{imageName}\t{namespaceName}\t{typeName}\t{methodName}\t{methodIndex}\t0x{method.token:X8}\t0x{pointer:X}\t0x{native.GetRVA(pointer):X}\t0x{offset:X}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR {imageName} {typeName}.{methodName}: {ex.Message}");
            }
        }
    }
}
return 0;
