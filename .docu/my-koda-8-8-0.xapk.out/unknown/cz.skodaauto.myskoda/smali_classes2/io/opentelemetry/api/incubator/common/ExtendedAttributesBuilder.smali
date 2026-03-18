.class public interface abstract Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static synthetic a(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Z
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->lambda$remove$2(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic b(Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->lambda$putAll$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->lambda$putAll$1(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$putAll$0(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$putAll$1(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$remove$2(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Z
    .locals 2

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getType()Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    return p0
.end method


# virtual methods
.method public abstract build()Lio/opentelemetry/api/incubator/common/ExtendedAttributes;
.end method

.method public put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation

    if-eqz p1, :cond_1

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    if-nez p2, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    :cond_1
    :goto_0
    return-object p0
.end method

.method public varargs put(Lio/opentelemetry/api/common/AttributeKey;[Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/util/List<",
            "TT;>;>;[TT;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation

    if-nez p2, :cond_0

    return-object p0

    .line 9
    :cond_0
    invoke-static {p2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public abstract put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation
.end method

.method public put(Ljava/lang/String;D)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    .line 5
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->doubleKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public put(Ljava/lang/String;J)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    .line 4
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public put(Ljava/lang/String;Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributes;",
            ")",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation

    .line 7
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->extendedAttributesKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public put(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    .line 3
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public put(Ljava/lang/String;Z)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    .line 6
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public varargs put(Ljava/lang/String;[D)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    if-nez p2, :cond_0

    return-object p0

    .line 11
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->doubleArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;->toList([D)Ljava/util/List;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public varargs put(Ljava/lang/String;[J)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    if-nez p2, :cond_0

    return-object p0

    .line 10
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->longArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;->toList([J)Ljava/util/List;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public varargs put(Ljava/lang/String;[Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    if-nez p2, :cond_0

    return-object p0

    .line 8
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->stringArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public varargs put(Ljava/lang/String;[Z)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0

    if-nez p2, :cond_0

    return-object p0

    .line 12
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->booleanArrayKey(Ljava/lang/String;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-static {p2}, Lio/opentelemetry/api/incubator/common/ArrayBackedExtendedAttributesBuilder;->toList([Z)Ljava/util/List;

    move-result-object p2

    invoke-interface {p0, p1, p2}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->put(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 2

    if-nez p1, :cond_0

    return-object p0

    .line 1
    :cond_0
    new-instance v0, Lio/opentelemetry/api/incubator/common/a;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/incubator/common/a;-><init>(Ljava/lang/Object;I)V

    invoke-interface {p1, v0}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    return-object p0
.end method

.method public putAll(Lio/opentelemetry/api/incubator/common/ExtendedAttributes;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 2

    if-nez p1, :cond_0

    return-object p0

    .line 2
    :cond_0
    new-instance v0, Lio/opentelemetry/api/incubator/common/a;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/api/incubator/common/a;-><init>(Ljava/lang/Object;I)V

    invoke-interface {p1, v0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributes;->forEach(Ljava/util/function/BiConsumer;)V

    return-object p0
.end method

.method public remove(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->fromAttributeKey(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    move-result-object p1

    invoke-interface {p0, p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->remove(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    return-object p0
.end method

.method public remove(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation

    if-eqz p1, :cond_1

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    new-instance v0, Lio/opentelemetry/api/incubator/common/b;

    invoke-direct {v0, p1}, Lio/opentelemetry/api/incubator/common/b;-><init>(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;)V

    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;->removeIf(Ljava/util/function/Predicate;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;

    move-result-object p0

    :cond_1
    :goto_0
    return-object p0
.end method

.method public abstract removeIf(Ljava/util/function/Predicate;)Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "*>;>;)",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributesBuilder;"
        }
    .end annotation
.end method
