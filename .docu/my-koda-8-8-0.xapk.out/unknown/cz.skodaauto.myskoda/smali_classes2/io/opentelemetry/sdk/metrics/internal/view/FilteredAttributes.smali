.class abstract Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/common/Attributes;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;,
        Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$RegularFilteredAttributes;
    }
.end annotation


# instance fields
.field private final hashcode:I

.field private final size:I

.field private final sourceData:[Ljava/lang/Object;


# direct methods
.method private constructor <init>([Ljava/lang/Object;II)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 4
    iput p2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->hashcode:I

    .line 5
    iput p3, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->size:I

    return-void
.end method

.method public synthetic constructor <init>([Ljava/lang/Object;IILio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;-><init>([Ljava/lang/Object;II)V

    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->lambda$convertToStandardImplementation$0(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static convertToStandardImplementation(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lio/opentelemetry/sdk/metrics/internal/view/e;

    .line 6
    .line 7
    invoke-direct {v1, v0}, Lio/opentelemetry/sdk/metrics/internal/view/e;-><init>(Lio/opentelemetry/api/common/AttributesBuilder;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {p0, v1}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static create(Lio/opentelemetry/api/common/Attributes;Ljava/util/Set;)Lio/opentelemetry/api/common/Attributes;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/Set<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    .line 1
    instance-of v0, p0, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->convertToStandardImplementation(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    instance-of v0, p0, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;

    .line 10
    .line 11
    if-eqz v0, :cond_7

    .line 12
    .line 13
    move-object v0, p0

    .line 14
    check-cast v0, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;

    .line 15
    .line 16
    invoke-virtual {v0}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->getData()[Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    if-le v0, v1, :cond_1

    .line 27
    .line 28
    new-instance v0, Ljava/util/BitSet;

    .line 29
    .line 30
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->size()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    invoke-direct {v0, p0}, Ljava/util/BitSet;-><init>(I)V

    .line 35
    .line 36
    .line 37
    :goto_0
    move-object v5, v0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/4 v0, 0x0

    .line 40
    goto :goto_0

    .line 41
    :goto_1
    const/4 p0, 0x0

    .line 42
    const/4 v0, 0x1

    .line 43
    move v4, p0

    .line 44
    move v3, v0

    .line 45
    move-object v1, v5

    .line 46
    move v5, v4

    .line 47
    :goto_2
    array-length v6, v2

    .line 48
    if-ge p0, v6, :cond_4

    .line 49
    .line 50
    div-int/lit8 v6, p0, 0x2

    .line 51
    .line 52
    aget-object v7, v2, p0

    .line 53
    .line 54
    invoke-interface {p1, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    if-nez v7, :cond_3

    .line 59
    .line 60
    if-eqz v1, :cond_2

    .line 61
    .line 62
    invoke-virtual {v1, v6}, Ljava/util/BitSet;->set(I)V

    .line 63
    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_2
    shl-int v6, v0, v6

    .line 67
    .line 68
    or-int/2addr v5, v6

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    mul-int/lit8 v3, v3, 0x1f

    .line 71
    .line 72
    aget-object v6, v2, p0

    .line 73
    .line 74
    const/16 v7, 0x1f

    .line 75
    .line 76
    invoke-static {v3, v6, v7}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    add-int/lit8 v6, p0, 0x1

    .line 81
    .line 82
    aget-object v6, v2, v6

    .line 83
    .line 84
    invoke-virtual {v6}, Ljava/lang/Object;->hashCode()I

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    add-int/2addr v3, v6

    .line 89
    add-int/lit8 v4, v4, 0x1

    .line 90
    .line 91
    :goto_3
    add-int/lit8 p0, p0, 0x2

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_4
    if-nez v4, :cond_5

    .line 95
    .line 96
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :cond_5
    if-eqz v1, :cond_6

    .line 102
    .line 103
    move-object v5, v1

    .line 104
    new-instance v1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$RegularFilteredAttributes;

    .line 105
    .line 106
    const/4 v6, 0x0

    .line 107
    invoke-direct/range {v1 .. v6}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$RegularFilteredAttributes;-><init>([Ljava/lang/Object;IILjava/util/BitSet;Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$1;)V

    .line 108
    .line 109
    .line 110
    return-object v1

    .line 111
    :cond_6
    move p0, v5

    .line 112
    new-instance v1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;

    .line 113
    .line 114
    const/4 v6, 0x0

    .line 115
    invoke-direct/range {v1 .. v6}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$SmallFilteredAttributes;-><init>([Ljava/lang/Object;IIILio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes$1;)V

    .line 116
    .line 117
    .line 118
    return-object v1

    .line 119
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string p1, "Expected ImmutableKeyValuePairs based implementation of Attributes. This is a programming error."

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0
.end method

.method private static synthetic lambda$convertToStandardImplementation$0(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->putInBuilder(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static putInBuilder(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)V"
        }
    .end annotation

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public asMap()Ljava/util/Map;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->size:I

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 10
    .line 11
    array-length v2, v2

    .line 12
    if-ge v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 21
    .line 22
    aget-object v3, v2, v1

    .line 23
    .line 24
    check-cast v3, Lio/opentelemetry/api/common/AttributeKey;

    .line 25
    .line 26
    add-int/lit8 v4, v1, 0x1

    .line 27
    .line 28
    aget-object v2, v2, v4

    .line 29
    .line 30
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    :cond_0
    add-int/lit8 v1, v1, 0x2

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_a

    .line 7
    .line 8
    instance-of v2, p1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;

    .line 9
    .line 10
    if-nez v2, :cond_1

    .line 11
    .line 12
    goto/16 :goto_4

    .line 13
    .line 14
    :cond_1
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;

    .line 15
    .line 16
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->size()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->size()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-eq v2, v3, :cond_2

    .line 25
    .line 26
    return v1

    .line 27
    :cond_2
    move v2, v1

    .line 28
    move v3, v2

    .line 29
    :goto_0
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 30
    .line 31
    array-length v4, v4

    .line 32
    if-lt v2, v4, :cond_3

    .line 33
    .line 34
    move v4, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_3
    move v4, v1

    .line 37
    :goto_1
    iget-object v5, p1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 38
    .line 39
    array-length v5, v5

    .line 40
    if-lt v3, v5, :cond_4

    .line 41
    .line 42
    move v5, v0

    .line 43
    goto :goto_2

    .line 44
    :cond_4
    move v5, v1

    .line 45
    :goto_2
    if-nez v4, :cond_5

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-nez v6, :cond_5

    .line 52
    .line 53
    add-int/lit8 v2, v2, 0x2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_5
    if-nez v5, :cond_6

    .line 57
    .line 58
    invoke-virtual {p1, v3}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    if-nez v6, :cond_6

    .line 63
    .line 64
    :goto_3
    add-int/lit8 v3, v3, 0x2

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_6
    if-eqz v4, :cond_7

    .line 68
    .line 69
    if-eqz v5, :cond_7

    .line 70
    .line 71
    return v0

    .line 72
    :cond_7
    if-eq v4, v5, :cond_8

    .line 73
    .line 74
    return v1

    .line 75
    :cond_8
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 76
    .line 77
    aget-object v4, v4, v2

    .line 78
    .line 79
    iget-object v5, p1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 80
    .line 81
    aget-object v5, v5, v3

    .line 82
    .line 83
    invoke-static {v4, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    if-eqz v4, :cond_a

    .line 88
    .line 89
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 90
    .line 91
    add-int/lit8 v5, v2, 0x1

    .line 92
    .line 93
    aget-object v4, v4, v5

    .line 94
    .line 95
    iget-object v5, p1, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 96
    .line 97
    add-int/lit8 v6, v3, 0x1

    .line 98
    .line 99
    aget-object v5, v5, v6

    .line 100
    .line 101
    invoke-static {v4, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-nez v4, :cond_9

    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_9
    add-int/lit8 v2, v2, 0x2

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_a
    :goto_4
    return v1
.end method

.method public forEach(Ljava/util/function/BiConsumer;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiConsumer<",
            "-",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;-",
            "Ljava/lang/Object;",
            ">;)V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 3
    .line 4
    array-length v1, v1

    .line 5
    if-ge v0, v1, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 14
    .line 15
    aget-object v2, v1, v0

    .line 16
    .line 17
    check-cast v2, Lio/opentelemetry/api/common/AttributeKey;

    .line 18
    .line 19
    add-int/lit8 v3, v0, 0x1

    .line 20
    .line 21
    aget-object v1, v1, v3

    .line 22
    .line 23
    invoke-interface {p1, v2, v1}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    add-int/lit8 v0, v0, 0x2

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return-void
.end method

.method public get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 7
    .line 8
    array-length v3, v2

    .line 9
    if-ge v1, v3, :cond_2

    .line 10
    .line 11
    aget-object v2, v2, v1

    .line 12
    .line 13
    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 26
    .line 27
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    aget-object p0, p0, v1

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    add-int/lit8 v1, v1, 0x2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    return-object v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->hashcode:I

    .line 2
    .line 3
    return p0
.end method

.method public abstract includeIndexInOutput(I)Z
.end method

.method public isEmpty()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public size()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->size:I

    .line 2
    .line 3
    return p0
.end method

.method public toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;
    .locals 5

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 7
    .line 8
    array-length v2, v2

    .line 9
    if-ge v1, v2, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 18
    .line 19
    aget-object v3, v2, v1

    .line 20
    .line 21
    check-cast v3, Lio/opentelemetry/api/common/AttributeKey;

    .line 22
    .line 23
    add-int/lit8 v4, v1, 0x1

    .line 24
    .line 25
    aget-object v2, v2, v4

    .line 26
    .line 27
    invoke-static {v0, v3, v2}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->putInBuilder(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    add-int/lit8 v1, v1, 0x2

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/StringJoiner;

    .line 2
    .line 3
    const-string v1, "FilteredAttributes{"

    .line 4
    .line 5
    const-string v2, "}"

    .line 6
    .line 7
    const-string v3, ","

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)V

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 14
    .line 15
    array-length v2, v2

    .line 16
    if-ge v1, v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->includeIndexInOutput(I)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    new-instance v2, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 30
    .line 31
    aget-object v3, v3, v1

    .line 32
    .line 33
    check-cast v3, Lio/opentelemetry/api/common/AttributeKey;

    .line 34
    .line 35
    invoke-interface {v3}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v3, "="

    .line 43
    .line 44
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/view/FilteredAttributes;->sourceData:[Ljava/lang/Object;

    .line 48
    .line 49
    add-int/lit8 v4, v1, 0x1

    .line 50
    .line 51
    aget-object v3, v3, v4

    .line 52
    .line 53
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-virtual {v0, v2}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 61
    .line 62
    .line 63
    :cond_0
    add-int/lit8 v1, v1, 0x2

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    invoke-virtual {v0}, Ljava/util/StringJoiner;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method
