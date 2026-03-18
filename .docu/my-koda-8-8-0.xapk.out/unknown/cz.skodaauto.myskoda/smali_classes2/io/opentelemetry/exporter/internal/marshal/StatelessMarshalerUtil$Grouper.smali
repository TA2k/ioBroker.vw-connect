.class Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Grouper"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/function/Consumer<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

.field private getInstrumentationScope:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;"
        }
    .end annotation
.end field

.field private getResource:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            ">;"
        }
    .end annotation
.end field

.field private result:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "TT;>;>;>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;-><init>()V

    return-void
.end method


# virtual methods
.method public accept(Ljava/lang/Object;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->getResource:Ljava/util/function/Function;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lio/opentelemetry/sdk/resources/Resource;

    .line 8
    .line 9
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->result:Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Ljava/util/Map;

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 20
    .line 21
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getIdentityMap()Ljava/util/Map;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->result:Ljava/util/Map;

    .line 26
    .line 27
    invoke-interface {v2, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->getInstrumentationScope:Ljava/util/function/Function;

    .line 31
    .line 32
    invoke-interface {v0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 37
    .line 38
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Ljava/util/List;

    .line 43
    .line 44
    if-nez v2, :cond_1

    .line 45
    .line 46
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 47
    .line 48
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getList()Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-interface {v1, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    :cond_1
    invoke-interface {v2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public initialize(Ljava/util/Map;Ljava/util/function/Function;Ljava/util/function/Function;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "TT;>;>;>;",
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            ">;",
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->result:Ljava/util/Map;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->getResource:Ljava/util/function/Function;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->getInstrumentationScope:Ljava/util/function/Function;

    .line 6
    .line 7
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 8
    .line 9
    return-void
.end method
