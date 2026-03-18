.class public final Lio/opentelemetry/sdk/metrics/ViewBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

.field private cardinalityLimit:I

.field private description:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private name:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private processor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/sdk/metrics/Aggregation;->defaultAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 9
    .line 10
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->noop()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->processor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 15
    .line 16
    const/16 v0, 0x7d0

    .line 17
    .line 18
    iput v0, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->cardinalityLimit:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public addAttributesProcessor(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->processor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->then(Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->processor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 8
    .line 9
    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/metrics/View;
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->name:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->description:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->processor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 8
    .line 9
    iget p0, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->cardinalityLimit:I

    .line 10
    .line 11
    invoke-static {v0, v1, v2, v3, p0}, Lio/opentelemetry/sdk/metrics/View;->create(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/Aggregation;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;I)Lio/opentelemetry/sdk/metrics/View;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public setAggregation(Lio/opentelemetry/sdk/metrics/Aggregation;)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 1

    .line 1
    instance-of v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 9
    .line 10
    const-string p1, "Custom Aggregation implementations are currently not supported. Use one of the standard implementations returned by the static factories in the Aggregation class."

    .line 11
    .line 12
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method

.method public setAttributeFilter(Ljava/util/Set;)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/ViewBuilder;"
        }
    .end annotation

    .line 1
    const-string v0, "keysToRetain"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    const/4 v0, 0x0

    .line 2
    invoke-static {p1, v0}, Lio/opentelemetry/sdk/internal/IncludeExcludePredicate;->createExactMatching(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/function/Predicate;

    move-result-object p1

    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/ViewBuilder;->setAttributeFilter(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/metrics/ViewBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setAttributeFilter(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/ViewBuilder;"
        }
    .end annotation

    .line 3
    const-string v0, "keyFilter"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->filterByKeyName(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->processor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    return-object p0
.end method

.method public setCardinalityLimit(I)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 0

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    iput p1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->cardinalityLimit:I

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 7
    .line 8
    const-string p1, "cardinalityLimit must be > 0"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public setName(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/ViewBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/ViewBuilder;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
