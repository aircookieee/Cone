using System.Text;
using Il2CppDumper;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: MetadataExplorer <repaired-metadata.dat> <output-directory>");
    return 2;
}

using var input = new MemoryStream(File.ReadAllBytes(args[0]), writable: true);
var metadata = new Metadata(input);
var output = args[1];
Directory.CreateDirectory(output);

using var assemblies = new StreamWriter(Path.Combine(output, "assemblies.tsv"), false, new UTF8Encoding(false));
using var types = new StreamWriter(Path.Combine(output, "game_types.tsv"), false, new UTF8Encoding(false));
using var methods = new StreamWriter(Path.Combine(output, "game_methods.tsv"), false, new UTF8Encoding(false));
using var protoFields = new StreamWriter(Path.Combine(output, "protobuf_fields.tsv"), false, new UTF8Encoding(false));
assemblies.WriteLine("image_index\timage\ttype_start\ttype_count");
types.WriteLine("image\tnamespace\ttype\ttype_index\tmethod_count");
methods.WriteLine("image\tnamespace\ttype\tmethod\tmethod_index");
protoFields.WriteLine("image\tnamespace\ttype\tfield_constant\tfield_number\tfield_index");

string GetName(uint index)
{
    if (index >= metadata.header.stringSize) return $"<bad-string-index:{index}>";
    var value = metadata.GetStringFromIndex(index);
    return value.Length > 160 || value.Any(char.IsControl)
        ? $"<protected-string:{index}>"
        : value;
}

static bool IsGameAssembly(string name) =>
    name.StartsWith("App.", StringComparison.OrdinalIgnoreCase) ||
    name.StartsWith("Fwk", StringComparison.OrdinalIgnoreCase) ||
    new[] { "Assembly-CSharp", "Conel", "HTTPComm", "DeltaComm", "Cryptograph", "Domain", "fbschema", "Adv", "Sirius", "FTLiveSimulator" }
        .Any(prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

var selectedImages = 0;
var selectedTypes = 0;
var selectedMethods = 0;
var skippedTypes = 0;
var skippedMethods = 0;
var selectedProtoFields = 0;
for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
{
    var image = metadata.imageDefs[imageIndex];
    var imageName = GetName(image.nameIndex);
    assemblies.WriteLine($"{imageIndex}\t{imageName}\t{image.typeStart}\t{image.typeCount}");
    if (!IsGameAssembly(imageName)) continue;
    selectedImages++;

    var typeEnd = (long)image.typeStart + image.typeCount;
    if (image.typeStart < 0 || typeEnd > metadata.typeDefs.Length)
    {
        skippedTypes += (int)image.typeCount;
        continue;
    }
    for (var typeIndex = image.typeStart; typeIndex < typeEnd; typeIndex++)
    {
        var type = metadata.typeDefs[typeIndex];
        var namespaceName = GetName(type.namespaceIndex);
        var typeName = GetName(type.nameIndex);
        types.WriteLine($"{imageName}\t{namespaceName}\t{typeName}\t{typeIndex}\t{type.method_count}");
        selectedTypes++;

        if (imageName.StartsWith("App.Protobuf", StringComparison.OrdinalIgnoreCase))
        {
            var fieldEnd = (long)type.fieldStart + type.field_count;
            if (type.fieldStart >= 0 && fieldEnd <= metadata.fieldDefs.Length)
            {
                for (var fieldIndex = type.fieldStart; fieldIndex < fieldEnd; fieldIndex++)
                {
                    var fieldName = GetName(metadata.fieldDefs[fieldIndex].nameIndex);
                    if (!fieldName.EndsWith("FieldNumber", StringComparison.Ordinal) ||
                        !metadata.GetFieldDefaultValueFromIndex(fieldIndex, out var fieldDefault) ||
                        fieldDefault.dataIndex < 0)
                        continue;
                    try
                    {
                        metadata.Position = metadata.GetDefaultValueFromIndex(fieldDefault.dataIndex);
                        var fieldNumber = metadata.Reader.ReadCompressedInt32();
                        if (fieldNumber is <= 0 or > 536870911) continue;
                        protoFields.WriteLine($"{imageName}\t{namespaceName}\t{typeName}\t{fieldName}\t{fieldNumber}\t{fieldIndex}");
                        selectedProtoFields++;
                    }
                    catch (Exception)
                    {
                        // A damaged default value must not hide the rest of the index.
                    }
                }
            }
        }

        var methodEnd = (long)type.methodStart + type.method_count;
        if (type.methodStart < 0 || methodEnd > metadata.methodDefs.Length)
        {
            skippedMethods += type.method_count;
            continue;
        }
        for (var methodIndex = type.methodStart; methodIndex < methodEnd; methodIndex++)
        {
            var methodName = GetName(metadata.methodDefs[methodIndex].nameIndex);
            methods.WriteLine($"{imageName}\t{namespaceName}\t{typeName}\t{methodName}\t{methodIndex}");
            selectedMethods++;
        }
    }
}

Console.WriteLine($"Metadata version: {metadata.Version}");
Console.WriteLine($"Images: {metadata.imageDefs.Length}; selected game images: {selectedImages}");
Console.WriteLine($"Game types: {selectedTypes}; methods: {selectedMethods}");
Console.WriteLine($"Protobuf field numbers: {selectedProtoFields}");
Console.WriteLine($"Skipped types: {skippedTypes}; methods: {skippedMethods}");
Console.WriteLine($"Output: {Path.GetFullPath(output)}");
return 0;
