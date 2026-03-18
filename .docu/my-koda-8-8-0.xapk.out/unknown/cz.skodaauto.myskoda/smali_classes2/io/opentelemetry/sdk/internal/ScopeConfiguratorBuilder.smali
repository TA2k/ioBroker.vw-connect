.class public final Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;,
        Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeNameMatcher;,
        Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
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

.field private defaultScopeConfig:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;)V
    .locals 1
    .param p1    # Lio/opentelemetry/sdk/internal/ScopeConfigurator;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "TT;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->conditions:Ljava/util/List;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->lambda$nameEquals$0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static synthetic lambda$nameEquals$0(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static nameEquals(Ljava/lang/String;)Ljava/util/function/Predicate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeNameMatcher;

    .line 2
    .line 3
    new-instance v1, Lio/opentelemetry/api/internal/a;

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    invoke-direct {v1, p0, v2}, Lio/opentelemetry/api/internal/a;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeNameMatcher;-><init>(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$1;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static nameMatchesGlob(Ljava/lang/String;)Ljava/util/function/Predicate;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeNameMatcher;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/GlobUtil;->createGlobPatternPredicate(Ljava/lang/String;)Ljava/util/function/Predicate;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeNameMatcher;-><init>(Ljava/util/function/Predicate;Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$1;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method


# virtual methods
.method public addCondition(Ljava/util/function/Predicate;Ljava/lang/Object;)Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;TT;)",
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->conditions:Ljava/util/List;

    .line 2
    .line 3
    new-instance v1, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p1, p2, v2}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$Condition;-><init>(Ljava/util/function/Predicate;Ljava/lang/Object;Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$1;)V

    .line 7
    .line 8
    .line 9
    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/internal/ScopeConfigurator;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/sdk/internal/ScopeConfigurator<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->baseScopeConfigurator:Lio/opentelemetry/sdk/internal/ScopeConfigurator;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->defaultScopeConfig:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->conditions:Ljava/util/List;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v0, v1, v2, p0, v3}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$ScopeConfiguratorImpl;-><init>(Lio/opentelemetry/sdk/internal/ScopeConfigurator;Ljava/lang/Object;Ljava/util/List;Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder$1;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public setDefault(Ljava/lang/Object;)Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)",
            "Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->defaultScopeConfig:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method
