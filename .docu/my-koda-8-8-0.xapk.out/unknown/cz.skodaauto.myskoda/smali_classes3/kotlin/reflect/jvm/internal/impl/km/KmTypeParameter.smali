.class public final Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final extensions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeParameterExtension;",
            ">;"
        }
    .end annotation
.end field

.field private flags:I

.field private id:I

.field private name:Ljava/lang/String;

.field private final upperBounds:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmType;",
            ">;"
        }
    .end annotation
.end field

.field private variance:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;


# direct methods
.method public constructor <init>(ILjava/lang/String;ILkotlin/reflect/jvm/internal/impl/km/KmVariance;)V
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "variance"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->flags:I

    .line 15
    .line 16
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->name:Ljava/lang/String;

    .line 17
    .line 18
    iput p3, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->id:I

    .line 19
    .line 20
    iput-object p4, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->variance:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 21
    .line 22
    new-instance p1, Ljava/util/ArrayList;

    .line 23
    .line 24
    const/4 p2, 0x1

    .line 25
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->upperBounds:Ljava/util/List;

    .line 29
    .line 30
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->Companion:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;

    .line 31
    .line 32
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;->getINSTANCES$kotlin_metadata()Ljava/util/List;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    check-cast p1, Ljava/lang/Iterable;

    .line 37
    .line 38
    new-instance p2, Ljava/util/ArrayList;

    .line 39
    .line 40
    const/16 p3, 0xa

    .line 41
    .line 42
    invoke-static {p1, p3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 43
    .line 44
    .line 45
    move-result p3

    .line 46
    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 47
    .line 48
    .line 49
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result p3

    .line 57
    if-eqz p3, :cond_0

    .line 58
    .line 59
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p3

    .line 63
    check-cast p3, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 64
    .line 65
    invoke-interface {p3}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->createTypeParameterExtension()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeParameterExtension;

    .line 66
    .line 67
    .line 68
    move-result-object p3

    .line 69
    invoke-interface {p2, p3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_0
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->extensions:Ljava/util/List;

    .line 74
    .line 75
    return-void
.end method


# virtual methods
.method public final getExtensions$kotlin_metadata()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeParameterExtension;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->extensions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFlags$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->flags:I

    .line 2
    .line 3
    return p0
.end method

.method public final getId()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->id:I

    .line 2
    .line 3
    return p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUpperBounds()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmType;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->upperBounds:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVariance()Lkotlin/reflect/jvm/internal/impl/km/KmVariance;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->variance:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setFlags$kotlin_metadata(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->flags:I

    .line 2
    .line 3
    return-void
.end method
