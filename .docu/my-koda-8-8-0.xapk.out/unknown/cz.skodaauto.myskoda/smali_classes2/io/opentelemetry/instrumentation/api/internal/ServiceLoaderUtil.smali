.class public final Lio/opentelemetry/instrumentation/api/internal/ServiceLoaderUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static volatile loadFunction:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/Iterable<",
            "*>;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/c;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/ServiceLoaderUtil;->loadFunction:Ljava/util/function/Function;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static load(Ljava/lang/Class;)Ljava/lang/Iterable;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Class<",
            "TT;>;)",
            "Ljava/lang/Iterable<",
            "TT;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/ServiceLoaderUtil;->loadFunction:Ljava/util/function/Function;

    .line 2
    .line 3
    invoke-interface {v0, p0}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    return-object p0
.end method

.method public static setLoadFunction(Ljava/util/function/Function;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/Iterable<",
            "*>;>;)V"
        }
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/ServiceLoaderUtil;->loadFunction:Ljava/util/function/Function;

    .line 2
    .line 3
    return-void
.end method
