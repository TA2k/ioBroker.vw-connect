.class public interface abstract Lio/opentelemetry/api/common/Attributes;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static builder()Lio/opentelemetry/api/common/AttributesBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/common/ArrayBackedAttributesBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/common/ArrayBackedAttributesBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static empty()Lio/opentelemetry/api/common/Attributes;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/common/ArrayBackedAttributes;->EMPTY:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object v0
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    if-eqz p0, :cond_1

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    if-nez p1, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    new-instance v0, Lio/opentelemetry/api/common/ArrayBackedAttributes;

    filled-new-array {p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    invoke-direct {v0, p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;-><init>([Ljava/lang/Object;)V

    return-object v0

    .line 3
    :cond_1
    :goto_0
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TU;>;TU;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    if-eqz p0, :cond_5

    .line 4
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_5

    if-nez p1, :cond_0

    goto :goto_1

    :cond_0
    if-eqz p2, :cond_4

    .line 5
    invoke-interface {p2}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_4

    if-nez p3, :cond_1

    goto :goto_0

    .line 6
    :cond_1
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p2}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 7
    invoke-static {p2, p3}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0

    .line 8
    :cond_2
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p2}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result v0

    if-lez v0, :cond_3

    .line 9
    new-instance v0, Lio/opentelemetry/api/common/ArrayBackedAttributes;

    filled-new-array {p2, p3, p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    invoke-direct {v0, p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;-><init>([Ljava/lang/Object;)V

    return-object v0

    .line 10
    :cond_3
    new-instance v0, Lio/opentelemetry/api/common/ArrayBackedAttributes;

    filled-new-array {p0, p1, p2, p3}, [Ljava/lang/Object;

    move-result-object p0

    invoke-direct {v0, p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;-><init>([Ljava/lang/Object;)V

    return-object v0

    .line 11
    :cond_4
    :goto_0
    invoke-static {p0, p1}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0

    .line 12
    :cond_5
    :goto_1
    invoke-static {p2, p3}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TU;>;TU;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TV;>;TV;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    .line 13
    filled-new-array/range {p0 .. p5}, [Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;->sortAndFilterToAttributes([Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            "W:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TU;>;TU;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TV;>;TV;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TW;>;TW;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    .line 14
    filled-new-array/range {p0 .. p7}, [Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;->sortAndFilterToAttributes([Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            "W:",
            "Ljava/lang/Object;",
            "X:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TU;>;TU;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TV;>;TV;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TW;>;TW;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TX;>;TX;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    .line 15
    filled-new-array/range {p0 .. p9}, [Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;->sortAndFilterToAttributes([Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0
.end method

.method public static of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            "W:",
            "Ljava/lang/Object;",
            "X:",
            "Ljava/lang/Object;",
            "Y:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TU;>;TU;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TV;>;TV;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TW;>;TW;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TX;>;TX;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TY;>;TY;)",
            "Lio/opentelemetry/api/common/Attributes;"
        }
    .end annotation

    .line 16
    filled-new-array/range {p0 .. p11}, [Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0}, Lio/opentelemetry/api/common/ArrayBackedAttributes;->sortAndFilterToAttributes([Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public abstract asMap()Ljava/util/Map;
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
.end method

.method public abstract forEach(Ljava/util/function/BiConsumer;)V
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
.end method

.method public abstract get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;
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
.end method

.method public abstract isEmpty()Z
.end method

.method public abstract size()I
.end method

.method public abstract toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;
.end method
