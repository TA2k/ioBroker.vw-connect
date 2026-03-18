.class public interface abstract Lio/opentelemetry/api/incubator/config/ConfigProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static synthetic a()Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/incubator/config/ConfigProvider;->lambda$noop$0()Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static synthetic lambda$noop$0()Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    return-object v0
.end method

.method public static noop()Lio/opentelemetry/api/incubator/config/ConfigProvider;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/config/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract getInstrumentationConfig()Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method
