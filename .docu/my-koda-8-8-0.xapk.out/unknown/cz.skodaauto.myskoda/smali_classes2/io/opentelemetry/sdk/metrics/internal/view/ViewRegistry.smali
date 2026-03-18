.class public final Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field static final DEFAULT_REGISTERED_VIEW:Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

.field static final DEFAULT_VIEW:Lio/opentelemetry/sdk/metrics/View;

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final instrumentDefaultRegisteredView:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/metrics/InstrumentType;",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;"
        }
    .end annotation
.end field

.field private final registeredViews:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/View;->builder()Lio/opentelemetry/sdk/metrics/ViewBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/ViewBuilder;->build()Lio/opentelemetry/sdk/metrics/View;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->DEFAULT_VIEW:Lio/opentelemetry/sdk/metrics/View;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->builder()Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    const-string v2, "*"

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->setName(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->build()Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    sget-object v2, Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;->NOOP:Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;

    .line 26
    .line 27
    const/16 v3, 0x7d0

    .line 28
    .line 29
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;->noSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    invoke-static {v1, v0, v2, v3, v4}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->create(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;ILio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;)Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->DEFAULT_REGISTERED_VIEW:Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 38
    .line 39
    const-class v0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->logger:Ljava/util/logging/Logger;

    .line 50
    .line 51
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;Ljava/util/List;)V
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;",
            "Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->instrumentDefaultRegisteredView:Ljava/util/Map;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/metrics/InstrumentType;->values()[Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    array-length v1, v0

    .line 16
    const/4 v2, 0x0

    .line 17
    :goto_0
    if-ge v2, v1, :cond_0

    .line 18
    .line 19
    aget-object v3, v0, v2

    .line 20
    .line 21
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->instrumentDefaultRegisteredView:Ljava/util/Map;

    .line 22
    .line 23
    invoke-static {}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->builder()Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    const-string v6, "*"

    .line 28
    .line 29
    invoke-virtual {v5, v6}, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->setName(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-virtual {v5}, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->build()Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    invoke-static {}, Lio/opentelemetry/sdk/metrics/View;->builder()Lio/opentelemetry/sdk/metrics/ViewBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    invoke-interface {p1, v3}, Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;->getDefaultAggregation(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    invoke-virtual {v6, v7}, Lio/opentelemetry/sdk/metrics/ViewBuilder;->setAggregation(Lio/opentelemetry/sdk/metrics/Aggregation;)Lio/opentelemetry/sdk/metrics/ViewBuilder;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    invoke-virtual {v6}, Lio/opentelemetry/sdk/metrics/ViewBuilder;->build()Lio/opentelemetry/sdk/metrics/View;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;->noop()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    invoke-interface {p2, v3}, Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;->getCardinalityLimit(Lio/opentelemetry/sdk/metrics/InstrumentType;)I

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;->noSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    invoke-static {v5, v6, v7, v8, v9}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->create(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;ILio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;)Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-interface {v4, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    add-int/lit8 v2, v2, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->registeredViews:Ljava/util/List;

    .line 76
    .line 77
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->lambda$create$0(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static applyAdviceToDefaultView(Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;)Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getInstrumentSelector()Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/view/AdviceAttributesProcessor;

    .line 10
    .line 11
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;->getAttributes()Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    check-cast p1, Ljava/util/List;

    .line 19
    .line 20
    invoke-direct {v2, p1}, Lio/opentelemetry/sdk/metrics/internal/view/AdviceAttributesProcessor;-><init>(Ljava/util/List;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getCardinalityLimit()I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {v0, v1, v2, p1, p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->create(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;ILio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;)Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public static create()Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;
    .locals 3

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/g;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 3
    invoke-static {}, Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;->defaultCardinalityLimitSelector()Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;

    move-result-object v1

    .line 4
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 5
    invoke-static {v0, v1, v2}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->create(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    move-result-object v0

    return-object v0
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;",
            "Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, p2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-direct {v0, p0, p1, v1}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;-><init>(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/export/CardinalityLimitSelector;Ljava/util/List;)V

    return-object v0
.end method

.method private static synthetic lambda$create$0(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/Aggregation;->defaultAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static matchesMeter(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getMeterName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getMeterName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    return v1

    .line 23
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getMeterVersion()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getMeterVersion()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getVersion()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_1

    .line 42
    .line 43
    return v1

    .line 44
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getMeterSchemaUrl()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getMeterSchemaUrl()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->getSchemaUrl()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-eqz p0, :cond_2

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    return v1

    .line 66
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 67
    return p0
.end method

.method private static matchesSelector(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getInstrumentType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getInstrumentType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    if-eq v0, v2, :cond_0

    .line 17
    .line 18
    return v1

    .line 19
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getInstrumentUnit()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getInstrumentUnit()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getUnit()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    return v1

    .line 40
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getInstrumentName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->getInstrumentName()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-static {v0}, Lio/opentelemetry/sdk/internal/GlobUtil;->createGlobPatternPredicate(Ljava/lang/String;)Ljava/util/function/Predicate;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-interface {v0, p1}, Ljava/util/function/Predicate;->test(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-nez p1, :cond_2

    .line 63
    .line 64
    return v1

    .line 65
    :cond_2
    invoke-static {p0, p2}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->matchesMeter(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    return p0
.end method


# virtual methods
.method public findViews(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/util/List;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ")",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->registeredViews:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const-string v3, " of type "

    .line 17
    .line 18
    const-string v4, " is incompatible with instrument "

    .line 19
    .line 20
    if-eqz v2, :cond_2

    .line 21
    .line 22
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 27
    .line 28
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getInstrumentSelector()Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-static {v5, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->matchesSelector(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Z

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    if-eqz v5, :cond_0

    .line 37
    .line 38
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    invoke-virtual {v5}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    check-cast v5, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 47
    .line 48
    invoke-interface {v5, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;->isCompatibleWithInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Z

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    if-eqz v5, :cond_1

    .line 53
    .line 54
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    sget-object v5, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->logger:Ljava/util/logging/Logger;

    .line 59
    .line 60
    sget-object v6, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 61
    .line 62
    new-instance v7, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v8, "View aggregation "

    .line 65
    .line 66
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    invoke-virtual {v2}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-static {v2}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregationUtil;->aggregationName(Lio/opentelemetry/sdk/metrics/Aggregation;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    invoke-virtual {v5, v6, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 113
    .line 114
    .line 115
    move-result p2

    .line 116
    if-nez p2, :cond_3

    .line 117
    .line 118
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    return-object p0

    .line 123
    :cond_3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->instrumentDefaultRegisteredView:Ljava/util/Map;

    .line 124
    .line 125
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 126
    .line 127
    .line 128
    move-result-object p2

    .line 129
    invoke-interface {p0, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 134
    .line 135
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 139
    .line 140
    .line 141
    move-result-object p2

    .line 142
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    check-cast p2, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 147
    .line 148
    invoke-interface {p2, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;->isCompatibleWithInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Z

    .line 149
    .line 150
    .line 151
    move-result p2

    .line 152
    if-nez p2, :cond_4

    .line 153
    .line 154
    sget-object p2, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->logger:Ljava/util/logging/Logger;

    .line 155
    .line 156
    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 157
    .line 158
    new-instance v1, Ljava/lang/StringBuilder;

    .line 159
    .line 160
    const-string v2, "Instrument default aggregation "

    .line 161
    .line 162
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregationUtil;->aggregationName(Lio/opentelemetry/sdk/metrics/Aggregation;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 188
    .line 189
    .line 190
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getType()Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    invoke-virtual {p2, v0, p0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    sget-object p0, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->DEFAULT_REGISTERED_VIEW:Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 208
    .line 209
    :cond_4
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getAdvice()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 210
    .line 211
    .line 212
    move-result-object p2

    .line 213
    invoke-virtual {p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;->hasAttributes()Z

    .line 214
    .line 215
    .line 216
    move-result p2

    .line 217
    if-eqz p2, :cond_5

    .line 218
    .line 219
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getAdvice()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->applyAdviceToDefaultView(Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;)Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    :cond_5
    invoke-static {p0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    return-object p0
.end method
