.class public abstract Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$JoinedAttributesProcessor;,
        Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AttributeKeyFilteringProcessor;,
        Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;,
        Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static append(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;-><init>(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static appendBaggageByKeyName(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$BaggageAppendingAttributesProcessor;-><init>(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static filterByKeyName(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AttributeKeyFilteringProcessor;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AttributeKeyFilteringProcessor;-><init>(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static noop()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;->NOOP:Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract process(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/common/Attributes;
.end method

.method public then(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;->NOOP:Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    if-ne p0, v0, :cond_1

    .line 7
    .line 8
    return-object p1

    .line 9
    :cond_1
    instance-of v0, p1, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$JoinedAttributesProcessor;

    .line 10
    .line 11
    if-eqz v0, :cond_2

    .line 12
    .line 13
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$JoinedAttributesProcessor;

    .line 14
    .line 15
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$JoinedAttributesProcessor;->prepend(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_2
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$JoinedAttributesProcessor;

    .line 21
    .line 22
    filled-new-array {p0, p1}, [Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$JoinedAttributesProcessor;-><init>(Ljava/util/Collection;)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public abstract usesContext()Z
.end method
