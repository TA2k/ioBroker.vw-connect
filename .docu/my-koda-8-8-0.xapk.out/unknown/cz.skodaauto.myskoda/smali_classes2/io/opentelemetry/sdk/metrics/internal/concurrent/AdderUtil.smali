.class public final Lio/opentelemetry/sdk/metrics/internal/concurrent/AdderUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lorg/codehaus/mojo/animal_sniffer/IgnoreJRERequirement;
.end annotation


# static fields
.field private static final hasJreAdder:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    :try_start_0
    const-string v0, "java.util.concurrent.atomic.DoubleAdder"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v0, "java.util.concurrent.atomic.LongAdder"

    .line 7
    .line 8
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :catch_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    sput-boolean v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/AdderUtil;->hasJreAdder:Z

    .line 15
    .line 16
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

.method public static createDoubleAdder()Lio/opentelemetry/sdk/metrics/internal/concurrent/DoubleAdder;
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/AdderUtil;->hasJreAdder:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/JreDoubleAdder;

    .line 6
    .line 7
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/JreDoubleAdder;-><init>()V

    .line 8
    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/AtomicLongDoubleAdder;

    .line 12
    .line 13
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/AtomicLongDoubleAdder;-><init>()V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public static createLongAdder()Lio/opentelemetry/sdk/metrics/internal/concurrent/LongAdder;
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/AdderUtil;->hasJreAdder:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/JreLongAdder;

    .line 6
    .line 7
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/JreLongAdder;-><init>()V

    .line 8
    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/concurrent/AtomicLongLongAdder;

    .line 12
    .line 13
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/concurrent/AtomicLongLongAdder;-><init>()V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method
