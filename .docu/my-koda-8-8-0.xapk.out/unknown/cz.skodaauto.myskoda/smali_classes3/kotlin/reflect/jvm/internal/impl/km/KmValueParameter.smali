.class public final Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private annotationParameterDefaultValue:Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

.field private final annotations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation
.end field

.field private final extensions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmValueParameterExtension;",
            ">;"
        }
    .end annotation
.end field

.field private flags:I

.field private name:Ljava/lang/String;

.field public type:Lkotlin/reflect/jvm/internal/impl/km/KmType;

.field private varargElementType:Lkotlin/reflect/jvm/internal/impl/km/KmType;


# direct methods
.method public constructor <init>(ILjava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->flags:I

    .line 10
    .line 11
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->name:Ljava/lang/String;

    .line 12
    .line 13
    new-instance p1, Ljava/util/ArrayList;

    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->annotations:Ljava/util/List;

    .line 20
    .line 21
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->Companion:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;

    .line 22
    .line 23
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;->getINSTANCES$kotlin_metadata()Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Ljava/lang/Iterable;

    .line 28
    .line 29
    new-instance p2, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 49
    .line 50
    invoke-interface {v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->createValueParameterExtension()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmValueParameterExtension;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-eqz v0, :cond_0

    .line 55
    .line 56
    invoke-interface {p2, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->extensions:Ljava/util/List;

    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final getAnnotationParameterDefaultValue()Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->annotationParameterDefaultValue:Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->annotations:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFlags$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->flags:I

    .line 2
    .line 3
    return p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getType()Lkotlin/reflect/jvm/internal/impl/km/KmType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->type:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "type"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final getVarargElementType()Lkotlin/reflect/jvm/internal/impl/km/KmType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->varargElementType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setAnnotationParameterDefaultValue(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->annotationParameterDefaultValue:Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 2
    .line 3
    return-void
.end method

.method public final setFlags$kotlin_metadata(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->flags:I

    .line 2
    .line 3
    return-void
.end method

.method public final setType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->type:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 7
    .line 8
    return-void
.end method

.method public final setVarargElementType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->varargElementType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-void
.end method
