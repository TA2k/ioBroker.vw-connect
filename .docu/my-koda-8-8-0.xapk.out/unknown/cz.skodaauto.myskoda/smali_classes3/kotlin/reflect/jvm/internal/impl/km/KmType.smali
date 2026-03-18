.class public final Lkotlin/reflect/jvm/internal/impl/km/KmType;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private abbreviatedType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

.field private final arguments:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;",
            ">;"
        }
    .end annotation
.end field

.field public classifier:Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

.field private final extensions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeExtension;",
            ">;"
        }
    .end annotation
.end field

.field private flags:I

.field private flexibleTypeUpperBound:Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;

.field private outerType:Lkotlin/reflect/jvm/internal/impl/km/KmType;


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    .line 11
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/KmType;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flags:I

    .line 3
    new-instance p1, Ljava/util/ArrayList;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->arguments:Ljava/util/List;

    .line 4
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->Companion:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;

    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;->getINSTANCES$kotlin_metadata()Ljava/util/List;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 6
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    .line 7
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 8
    invoke-interface {v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->createTypeExtension()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeExtension;

    move-result-object v1

    .line 9
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 10
    :cond_0
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->extensions:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    if-eqz p1, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 v1, 0x0

    .line 13
    :goto_0
    const-class v2, Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v1, :cond_2

    .line 21
    .line 22
    return v2

    .line 23
    :cond_2
    const-string v1, "null cannot be cast to non-null type kotlin.metadata.KmType"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 29
    .line 30
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flags:I

    .line 31
    .line 32
    iget v3, p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flags:I

    .line 33
    .line 34
    if-eq v1, v3, :cond_3

    .line 35
    .line 36
    return v2

    .line 37
    :cond_3
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getClassifier()Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getClassifier()Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_4

    .line 50
    .line 51
    return v2

    .line 52
    :cond_4
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->arguments:Ljava/util/List;

    .line 53
    .line 54
    iget-object v3, p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;->arguments:Ljava/util/List;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_5

    .line 61
    .line 62
    return v2

    .line 63
    :cond_5
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->outerType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 64
    .line 65
    iget-object v3, p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;->outerType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_6

    .line 72
    .line 73
    return v2

    .line 74
    :cond_6
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->abbreviatedType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 75
    .line 76
    iget-object v3, p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;->abbreviatedType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_7

    .line 83
    .line 84
    return v2

    .line 85
    :cond_7
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flexibleTypeUpperBound:Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;

    .line 86
    .line 87
    iget-object v3, p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flexibleTypeUpperBound:Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_8

    .line 94
    .line 95
    return v2

    .line 96
    :cond_8
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->extensions:Ljava/util/List;

    .line 97
    .line 98
    iget-object p1, p1, Lkotlin/reflect/jvm/internal/impl/km/KmType;->extensions:Ljava/util/List;

    .line 99
    .line 100
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    if-nez p0, :cond_9

    .line 105
    .line 106
    return v2

    .line 107
    :cond_9
    return v0
.end method

.method public final getAbbreviatedType()Lkotlin/reflect/jvm/internal/impl/km/KmType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->abbreviatedType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getArguments()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->arguments:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getClassifier()Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->classifier:Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "classifier"

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

.method public final getExtensions$kotlin_metadata()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeExtension;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->extensions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFlags$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flags:I

    .line 2
    .line 3
    return p0
.end method

.method public final getFlexibleTypeUpperBound()Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flexibleTypeUpperBound:Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOuterType()Lkotlin/reflect/jvm/internal/impl/km/KmType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->outerType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flags:I

    .line 2
    .line 3
    mul-int/lit8 v0, v0, 0x1f

    .line 4
    .line 5
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getClassifier()Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, v0

    .line 14
    mul-int/lit8 v1, v1, 0x1f

    .line 15
    .line 16
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->arguments:Ljava/util/List;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/2addr p0, v1

    .line 23
    return p0
.end method

.method public final setAbbreviatedType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->abbreviatedType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-void
.end method

.method public final setClassifier(Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->classifier:Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

    .line 7
    .line 8
    return-void
.end method

.method public final setFlags$kotlin_metadata(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flags:I

    .line 2
    .line 3
    return-void
.end method

.method public final setFlexibleTypeUpperBound(Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->flexibleTypeUpperBound:Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;

    .line 2
    .line 3
    return-void
.end method

.method public final setOuterType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmType;->outerType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-void
.end method
