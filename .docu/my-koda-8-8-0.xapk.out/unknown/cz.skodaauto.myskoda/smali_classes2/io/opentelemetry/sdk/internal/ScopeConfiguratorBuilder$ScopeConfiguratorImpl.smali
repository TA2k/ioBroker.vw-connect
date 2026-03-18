.class Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/internal/ScopeConfigurator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ScopeConfiguratorImpl"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private final baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "TT;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final conditions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final defaultScopeConfig:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;Ljava/lang/Object;Ljava/util/List;)V
    .locals 0
    .param p1    # Lio/opentelemetry/sdk/internal/ScopeConfigurator;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "TT;>;TT;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition<",
            "TT;>;>;)V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 4
    iput-object p2, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->defaultScopeConfig:Ljava/lang/Object;

    .line 5
    iput-object p3, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->conditions:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;Ljava/lang/Object;Ljava/util/List;Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;-><init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;Ljava/lang/Object;Ljava/util/List;)V

    return-void
.end method


# virtual methods
.method public apply(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ")TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    if-eqz v0, :cond_0

    .line 3
    invoke-interface {v0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    .line 4
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->conditions:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;

    .line 5
    invoke-static {v1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;->access$300(Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;)Ljava/util/function/Predicate;

    move-result-object v2

    invoke-interface {v2, p1}, Ljava/util/function/Predicate;->test(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    .line 6
    invoke-static {v1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;->access$400(Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    .line 7
    :cond_2
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->defaultScopeConfig:Ljava/lang/Object;

    return-object p0
.end method

.method public bridge synthetic apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    check-cast p1, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->apply(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/StringJoiner;

    .line 2
    .line 3
    const-string v1, "ScopeConfiguratorImpl{"

    .line 4
    .line 5
    const-string v2, "}"

    .line 6
    .line 7
    const-string v3, ", "

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "baseScopeConfigurator="

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v2, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 24
    .line 25
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {v0, v1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 33
    .line 34
    .line 35
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->defaultScopeConfig:Ljava/lang/Object;

    .line 36
    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    new-instance v1, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v2, "defaultScopeConfig="

    .line 42
    .line 43
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v2, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->defaultScopeConfig:Ljava/lang/Object;

    .line 47
    .line 48
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v0, v1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 56
    .line 57
    .line 58
    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v2, "conditions="

    .line 61
    .line 62
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;->conditions:Ljava/util/List;

    .line 66
    .line 67
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    new-instance v2, Lio/opentelemetry/sdk/internal/b;

    .line 72
    .line 73
    const/4 v3, 0x1

    .line 74
    invoke-direct {v2, v3}, Lio/opentelemetry/sdk/internal/b;-><init>(I)V

    .line 75
    .line 76
    .line 77
    invoke-interface {p0, v2}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    const-string v2, "["

    .line 82
    .line 83
    const-string v3, "]"

    .line 84
    .line 85
    const-string v4, ","

    .line 86
    .line 87
    invoke-static {v4, v2, v3}, Ljava/util/stream/Collectors;->joining(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/util/stream/Collector;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-interface {p0, v2}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    check-cast p0, Ljava/lang/String;

    .line 96
    .line 97
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-virtual {v0, p0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Ljava/util/StringJoiner;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0
.end method
