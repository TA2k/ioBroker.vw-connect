.class public Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final extensions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;",
            ">;"
        }
    .end annotation
.end field

.field private final strings:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;

.field private final versionRequirements:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableVersionRequirementTable;


# virtual methods
.method public final get(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "string"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->strings:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;->getStringIndex(Ljava/lang/String;)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final getClassName$kotlin_metadata(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->strings:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;

    .line 7
    .line 8
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->getClassNameIndex(Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;Ljava/lang/String;)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final getExtensions$kotlin_metadata()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->extensions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStrings()Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->strings:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVersionRequirements$kotlin_metadata()Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableVersionRequirementTable;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->versionRequirements:Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableVersionRequirementTable;

    .line 2
    .line 3
    return-object p0
.end method
