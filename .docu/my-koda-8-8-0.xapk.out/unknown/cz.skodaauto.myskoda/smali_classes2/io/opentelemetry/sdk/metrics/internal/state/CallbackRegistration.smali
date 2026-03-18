.class public final Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final callback:Ljava/lang/Runnable;

.field private final hasStorages:Z

.field private final instrumentDescriptors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            ">;"
        }
    .end annotation
.end field

.field private final observableMeasurements:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;",
            ">;"
        }
    .end annotation
.end field

.field private final throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(Ljava/util/List;Ljava/lang/Runnable;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;",
            ">;",
            "Ljava/lang/Runnable;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 5
    .line 6
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->logger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->observableMeasurements:Ljava/util/List;

    .line 14
    .line 15
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->callback:Ljava/lang/Runnable;

    .line 16
    .line 17
    invoke-interface {p1}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    new-instance v0, Lfx0/d;

    .line 22
    .line 23
    const/16 v1, 0x11

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lfx0/d;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p2, v0}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    invoke-static {}, Ljava/util/stream/Collectors;->toList()Ljava/util/stream/Collector;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-interface {p2, v0}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    check-cast p2, Ljava/util/List;

    .line 41
    .line 42
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->instrumentDescriptors:Ljava/util/List;

    .line 43
    .line 44
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    if-eqz p2, :cond_0

    .line 49
    .line 50
    invoke-interface {p1}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    new-instance p2, Lfx0/d;

    .line 55
    .line 56
    const/16 v0, 0x12

    .line 57
    .line 58
    invoke-direct {p2, v0}, Lfx0/d;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-interface {p1, p2}, Ljava/util/stream/Stream;->flatMap(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-interface {p1}, Ljava/util/stream/Stream;->findAny()Ljava/util/Optional;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-virtual {p1}, Ljava/util/Optional;->isPresent()Z

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->hasStorages:Z

    .line 74
    .line 75
    return-void

    .line 76
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "Callback with no instruments is not allowed"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)Ljava/util/stream/Stream;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->lambda$new$0(Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)Ljava/util/stream/Stream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJLio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->lambda$invokeCallback$1(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJLio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/util/List;Ljava/lang/Runnable;)Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;",
            ">;",
            "Ljava/lang/Runnable;",
            ")",
            "Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;-><init>(Ljava/util/List;Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static synthetic lambda$invokeCallback$1(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJLio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V
    .locals 2

    .line 1
    move-wide v0, p1

    .line 2
    move-object p1, p0

    .line 3
    move-object p0, p5

    .line 4
    move-wide p4, p3

    .line 5
    move-wide p2, v0

    .line 6
    invoke-virtual/range {p0 .. p5}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->setActiveReader(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJ)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method private static synthetic lambda$new$0(Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)Ljava/util/stream/Stream;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->getStorages()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public invokeCallback(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJ)V
    .locals 8

    .line 1
    const-string v1, "An exception occurred invoking callback for "

    .line 2
    .line 3
    iget-boolean v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->hasStorages:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->observableMeasurements:Ljava/util/List;

    .line 9
    .line 10
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/state/d;

    .line 11
    .line 12
    move-object v3, p1

    .line 13
    move-wide v4, p2

    .line 14
    move-wide v6, p4

    .line 15
    invoke-direct/range {v2 .. v7}, Lio/opentelemetry/sdk/metrics/internal/state/d;-><init>(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJ)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v0, v2}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 19
    .line 20
    .line 21
    :try_start_0
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->callback:Ljava/lang/Runnable;

    .line 22
    .line 23
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->observableMeasurements:Ljava/util/List;

    .line 27
    .line 28
    new-instance p1, Lfx0/a;

    .line 29
    .line 30
    const/4 p2, 0x2

    .line 31
    invoke-direct {p1, p2}, Lfx0/a;-><init>(I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    invoke-interface {p0, p1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception v0

    .line 39
    move-object p1, v0

    .line 40
    :try_start_1
    invoke-static {p1}, Lio/opentelemetry/sdk/internal/ThrowableUtil;->propagateIfFatal(Ljava/lang/Throwable;)V

    .line 41
    .line 42
    .line 43
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 44
    .line 45
    sget-object p3, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 46
    .line 47
    new-instance p4, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    invoke-direct {p4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p5, "."

    .line 56
    .line 57
    invoke-virtual {p4, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p4

    .line 64
    invoke-virtual {p2, p3, p4, p1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->observableMeasurements:Ljava/util/List;

    .line 68
    .line 69
    new-instance p1, Lfx0/a;

    .line 70
    .line 71
    const/4 p2, 0x2

    .line 72
    invoke-direct {p1, p2}, Lfx0/a;-><init>(I)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :catchall_1
    move-exception v0

    .line 77
    move-object p1, v0

    .line 78
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->observableMeasurements:Ljava/util/List;

    .line 79
    .line 80
    new-instance p2, Lfx0/a;

    .line 81
    .line 82
    const/4 p3, 0x2

    .line 83
    invoke-direct {p2, p3}, Lfx0/a;-><init>(I)V

    .line 84
    .line 85
    .line 86
    invoke-interface {p0, p2}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 87
    .line 88
    .line 89
    throw p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CallbackRegistration{instrumentDescriptors="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->instrumentDescriptors:Ljava/util/List;

    .line 9
    .line 10
    const-string v1, "}"

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
