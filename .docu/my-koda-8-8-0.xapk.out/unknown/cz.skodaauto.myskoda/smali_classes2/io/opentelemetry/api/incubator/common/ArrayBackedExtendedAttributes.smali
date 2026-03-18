.class final Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;
.super Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/common/ExtendedAttributes;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/api/internal/ImmutableKeyValuePairs<",
        "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
        "*>;",
        "Ljava/lang/Object;",
        ">;",
        "Lio/opentelemetry/api/incubator/common/ExtendedAttributes;"
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field static final EMPTY:Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

.field private static final KEY_COMPARATOR_FOR_CONSTRUCTION:Ljava/util/Comparator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Comparator<",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;>;"
        }
    .end annotation
.end field


# instance fields
.field private attributes:Lio/opentelemetry/api/common/Attributes;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfx0/d;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lfx0/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Ljava/util/Comparator;->comparing(Ljava/util/function/Function;)Ljava/util/Comparator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->KEY_COMPARATOR_FOR_CONSTRUCTION:Ljava/util/Comparator;

    .line 12
    .line 13
    invoke-static {}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->builder()Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-interface {v0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->build()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->EMPTY:Lio/opentelemetry/api/incubator/common/ExtendedAttributes;

    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>([Ljava/lang/Object;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;-><init>([Ljava/lang/Object;)V

    return-void
.end method

.method private constructor <init>([Ljava/lang/Object;Ljava/util/Comparator;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Ljava/lang/Object;",
            "Ljava/util/Comparator<",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;-><init>([Ljava/lang/Object;Ljava/util/Comparator;)V

    return-void
.end method

.method public static synthetic c(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->lambda$asAttributes$0(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$asAttributes$0(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->asAttributeKey()Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public static varargs sortAndFilterToAttributes([Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    array-length v1, p0

    .line 3
    if-ge v0, v1, :cond_1

    .line 4
    .line 5
    aget-object v1, p0, v0

    .line 6
    .line 7
    check-cast v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-interface {v1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    aput-object v1, p0, v0

    .line 23
    .line 24
    :cond_0
    add-int/lit8 v0, v0, 0x2

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    new-instance v0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;

    .line 28
    .line 29
    sget-object v1, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->KEY_COMPARATOR_FOR_CONSTRUCTION:Ljava/util/Comparator;

    .line 30
    .line 31
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;-><init>([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method


# virtual methods
.method public asAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Lio/opentelemetry/api/incubator/common/a;

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    invoke-direct {v1, v0, v2}, Lio/opentelemetry/api/incubator/common/a;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v1}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->forEach(Ljava/util/function/BiConsumer;)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iput-object v0, p0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 23
    .line 24
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributes;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 25
    .line 26
    return-object p0
.end method

.method public get(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public toBuilder()Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->data()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;-><init>(Ljava/util/List;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method
