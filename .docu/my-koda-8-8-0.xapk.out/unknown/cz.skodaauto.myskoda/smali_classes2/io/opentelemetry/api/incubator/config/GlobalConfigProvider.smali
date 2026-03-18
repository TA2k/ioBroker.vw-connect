.class public final Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final instance:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            ">;"
        }
    .end annotation
.end field

.field private static volatile setInstanceCaller:Ljava/lang/Throwable;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/api/incubator/config/ConfigProvider;->noop()Lio/opentelemetry/api/incubator/config/ConfigProvider;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;->instance:Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
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

.method public static get()Lio/opentelemetry/api/incubator/config/ConfigProvider;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;->instance:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lio/opentelemetry/api/incubator/config/ConfigProvider;

    .line 8
    .line 9
    return-object v0
.end method

.method public static resetForTest()V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;->instance:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/api/incubator/config/ConfigProvider;->noop()Lio/opentelemetry/api/incubator/config/ConfigProvider;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static set(Lio/opentelemetry/api/incubator/config/ConfigProvider;)V
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;->instance:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/api/incubator/config/ConfigProvider;->noop()Lio/opentelemetry/api/incubator/config/ConfigProvider;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    :cond_0
    invoke-virtual {v0, v1, p0}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    if-eq v2, v1, :cond_0

    .line 19
    .line 20
    invoke-static {}, Lio/opentelemetry/api/incubator/config/ConfigProvider;->noop()Lio/opentelemetry/api/incubator/config/ConfigProvider;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    if-ne p0, v0, :cond_2

    .line 25
    .line 26
    :goto_0
    new-instance p0, Ljava/lang/Throwable;

    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/Throwable;-><init>()V

    .line 29
    .line 30
    .line 31
    sput-object p0, Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;->setInstanceCaller:Ljava/lang/Throwable;

    .line 32
    .line 33
    return-void

    .line 34
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v0, "GlobalConfigProvider.set has already been called. GlobalConfigProvider.set must be called only once before any calls to GlobalConfigProvider.get. Previous invocation set to cause of this exception."

    .line 37
    .line 38
    sget-object v1, Lio/opentelemetry/api/incubator/config/GlobalConfigProvider;->setInstanceCaller:Ljava/lang/Throwable;

    .line 39
    .line 40
    invoke-direct {p0, v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 41
    .line 42
    .line 43
    throw p0
.end method
