.class final Lio/opentelemetry/sdk/metrics/SdkMeter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/Meter;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/SdkMeter$MultiWritableMetricStorage;
    }
.end annotation


# static fields
.field private static final INCUBATOR_AVAILABLE:Z

.field private static final NOOP_INSTRUMENT_NAME:Ljava/lang/String; = "noop"

.field private static final NOOP_METER:Lio/opentelemetry/api/metrics/Meter;

.field private static final VALID_INSTRUMENT_NAME_PATTERN:Ljava/util/regex/Pattern;

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final callbackLock:Ljava/lang/Object;

.field private final callbackRegistrations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;",
            ">;"
        }
    .end annotation
.end field

.field private final collectLock:Ljava/lang/Object;

.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private volatile meterEnabled:Z

.field private final meterProviderSharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

.field private final readerStorageRegistries:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            "Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/SdkMeter;

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
    sput-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    :try_start_0
    sget v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDefaultMeterProvider;->d:I
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    goto :goto_0

    .line 17
    :catch_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    sput-boolean v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->INCUBATOR_AVAILABLE:Z

    .line 19
    .line 20
    const-string v0, "([A-Za-z]){1}([A-Za-z0-9\\_\\-\\./]){0,254}"

    .line 21
    .line 22
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sput-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->VALID_INSTRUMENT_NAME_PATTERN:Ljava/util/regex/Pattern;

    .line 27
    .line 28
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const-string v1, "noop"

    .line 33
    .line 34
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/MeterProvider;->get(Ljava/lang/String;)Lio/opentelemetry/api/metrics/Meter;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->NOOP_METER:Lio/opentelemetry/api/metrics/Meter;

    .line 39
    .line 40
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/MeterConfig;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/internal/MeterConfig;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->collectLock:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackLock:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackRegistrations:Ljava/util/List;

    .line 24
    .line 25
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 26
    .line 27
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterProviderSharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 28
    .line 29
    invoke-interface {p3}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-static {}, Ljava/util/function/Function;->identity()Ljava/util/function/Function;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    new-instance p3, Lio/opentelemetry/sdk/metrics/c;

    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    invoke-direct {p3, v0}, Lio/opentelemetry/sdk/metrics/c;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-static {p2, p3}, Ljava/util/stream/Collectors;->toMap(Ljava/util/function/Function;Ljava/util/function/Function;)Ljava/util/stream/Collector;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    invoke-interface {p1, p2}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Ljava/util/Map;

    .line 52
    .line 53
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 54
    .line 55
    invoke-virtual {p4}, Lio/opentelemetry/sdk/metrics/internal/MeterConfig;->isEnabled()Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 60
    .line 61
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;)Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->lambda$new$0(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;)Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static checkValidInstrumentName(Ljava/lang/String;)Z
    .locals 4

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    sget-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->VALID_INSTRUMENT_NAME_PATTERN:Ljava/util/regex/Pattern;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    sget-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->logger:Ljava/util/logging/Logger;

    .line 18
    .line 19
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    const-string v2, "Instrument name \""

    .line 28
    .line 29
    const-string v3, "\" is invalid, returning noop instrument. Instrument names must consist of 255 or fewer characters including alphanumeric, _, ., -, /, and start with a letter."

    .line 30
    .line 31
    invoke-static {v2, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    new-instance v2, Ljava/lang/AssertionError;

    .line 36
    .line 37
    invoke-direct {v2}, Ljava/lang/AssertionError;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, v1, p0, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 41
    .line 42
    .line 43
    :cond_1
    const/4 p0, 0x0

    .line 44
    return p0
.end method

.method private static synthetic lambda$new$0(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;)Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;
    .locals 0

    .line 1
    new-instance p0, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;

    .line 2
    .line 3
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method


# virtual methods
.method public varargs batchCallback(Ljava/lang/Runnable;Lio/opentelemetry/api/metrics/ObservableMeasurement;[Lio/opentelemetry/api/metrics/ObservableMeasurement;)Lio/opentelemetry/api/metrics/BatchCallback;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    invoke-static {v0, p3}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    new-instance p2, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p3

    .line 21
    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lio/opentelemetry/api/metrics/ObservableMeasurement;

    .line 32
    .line 33
    instance-of v1, v0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 34
    .line 35
    if-nez v1, :cond_0

    .line 36
    .line 37
    sget-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->logger:Ljava/util/logging/Logger;

    .line 38
    .line 39
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 40
    .line 41
    const-string v2, "batchCallback called with instruments that were not created by the SDK."

    .line 42
    .line 43
    invoke-virtual {v0, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 48
    .line 49
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 50
    .line 51
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-nez v1, :cond_1

    .line 60
    .line 61
    sget-object v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->logger:Ljava/util/logging/Logger;

    .line 62
    .line 63
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 64
    .line 65
    const-string v2, "batchCallback called with instruments that belong to a different Meter."

    .line 66
    .line 67
    invoke-virtual {v0, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_2
    invoke-static {p2, p1}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->create(Ljava/util/List;Ljava/lang/Runnable;)Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->registerCallback(Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 80
    .line 81
    .line 82
    new-instance p2, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;

    .line 83
    .line 84
    invoke-direct {p2, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 85
    .line 86
    .line 87
    return-object p2
.end method

.method public collectAll(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;J)Ljava/util/Collection;
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            "J)",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackRegistrations:Ljava/util/List;

    .line 7
    .line 8
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 9
    .line 10
    .line 11
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 12
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->collectLock:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v2

    .line 15
    :try_start_1
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    move-object v3, v1

    .line 34
    check-cast v3, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterProviderSharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 37
    .line 38
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getStartEpochNanos()J

    .line 39
    .line 40
    .line 41
    move-result-wide v5

    .line 42
    move-object v4, p1

    .line 43
    move-wide v7, p2

    .line 44
    invoke-virtual/range {v3 .. v8}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->invokeCallback(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJ)V

    .line 45
    .line 46
    .line 47
    move-object p1, v4

    .line 48
    move-wide p2, v7

    .line 49
    goto :goto_0

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    move-object p0, v0

    .line 52
    goto :goto_2

    .line 53
    :cond_0
    move-object v4, p1

    .line 54
    move-wide v7, p2

    .line 55
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 56
    .line 57
    invoke-interface {p1, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;

    .line 62
    .line 63
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;->getStorages()Ljava/util/Collection;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    new-instance p2, Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 73
    .line 74
    .line 75
    move-result p3

    .line 76
    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 77
    .line 78
    .line 79
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    :cond_1
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result p3

    .line 87
    if-eqz p3, :cond_2

    .line 88
    .line 89
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p3

    .line 93
    move-object v3, p3

    .line 94
    check-cast v3, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;

    .line 95
    .line 96
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterProviderSharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 97
    .line 98
    invoke-virtual {p3}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    iget-object p3, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterProviderSharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 107
    .line 108
    invoke-virtual {p3}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getStartEpochNanos()J

    .line 109
    .line 110
    .line 111
    move-result-wide v0

    .line 112
    move-wide v8, v7

    .line 113
    move-wide v6, v0

    .line 114
    invoke-interface/range {v3 .. v9}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;->collect(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJ)Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 115
    .line 116
    .line 117
    move-result-object p3

    .line 118
    move-wide v7, v8

    .line 119
    invoke-interface {p3}, Lio/opentelemetry/sdk/metrics/data/MetricData;->isEmpty()Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    if-nez v0, :cond_1

    .line 124
    .line 125
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_2
    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    monitor-exit v2

    .line 134
    return-object p0

    .line 135
    :goto_2
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 136
    throw p0

    .line 137
    :catchall_1
    move-exception v0

    .line 138
    move-object p0, v0

    .line 139
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 140
    throw p0
.end method

.method public counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->checkValidInstrumentName(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->NOOP_METER:Lio/opentelemetry/api/metrics/Meter;

    .line 8
    .line 9
    const-string p1, "noop"

    .line 10
    .line 11
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/Meter;->counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->INCUBATOR_AVAILABLE:Z

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/IncubatingUtil;->createExtendedLongCounterBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkLongCounter$SdkLongCounterBuilder;

    .line 26
    .line 27
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkLongCounter$SdkLongCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public gaugeBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->checkValidInstrumentName(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->NOOP_METER:Lio/opentelemetry/api/metrics/Meter;

    .line 8
    .line 9
    const-string p1, "noop"

    .line 10
    .line 11
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/Meter;->gaugeBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->INCUBATOR_AVAILABLE:Z

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/IncubatingUtil;->createExtendedDoubleGaugeBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkDoubleGauge$SdkDoubleGaugeBuilder;

    .line 26
    .line 27
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkDoubleGauge$SdkDoubleGaugeBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->checkValidInstrumentName(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->NOOP_METER:Lio/opentelemetry/api/metrics/Meter;

    .line 8
    .line 9
    const-string p1, "noop"

    .line 10
    .line 11
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->INCUBATOR_AVAILABLE:Z

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/IncubatingUtil;->createExtendedDoubleHistogramBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;

    .line 26
    .line 27
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkDoubleHistogram$SdkDoubleHistogramBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public isMeterEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public registerCallback(Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackRegistrations:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public registerObservableMeasurement(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;
    .locals 8

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v2

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
    check-cast v2, Ljava/util/Map$Entry;

    .line 27
    .line 28
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 33
    .line 34
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;

    .line 39
    .line 40
    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getViewRegistry()Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-virtual {v4, p1, v5}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->findViews(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_0

    .line 61
    .line 62
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 67
    .line 68
    invoke-static {}, Lio/opentelemetry/sdk/metrics/Aggregation;->drop()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    invoke-virtual {v5}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    invoke-virtual {v7}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    if-ne v6, v7, :cond_1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    iget-boolean v6, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 84
    .line 85
    invoke-static {v3, v5, p1, v6}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->create(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Z)Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    invoke-virtual {v2, v5}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;->register(Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;)Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    check-cast v5, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 94
    .line 95
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_2
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 100
    .line 101
    invoke-static {p0, p1, v0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->create(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0
.end method

.method public registerSynchronousMetricStorage(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;
    .locals 8

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v2

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
    check-cast v2, Ljava/util/Map$Entry;

    .line 27
    .line 28
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 33
    .line 34
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;

    .line 39
    .line 40
    invoke-virtual {v3}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getViewRegistry()Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-virtual {v4, p1, v5}, Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;->findViews(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_0

    .line 61
    .line 62
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 67
    .line 68
    invoke-static {}, Lio/opentelemetry/sdk/metrics/Aggregation;->drop()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    invoke-virtual {v5}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    invoke-virtual {v7}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    if-ne v6, v7, :cond_1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    iget-object v6, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterProviderSharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 84
    .line 85
    invoke-virtual {v6}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getExemplarFilter()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    iget-boolean v7, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 90
    .line 91
    invoke-static {v3, v5, p1, v6, v7}, Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;->create(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Z)Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    invoke-virtual {v2, v5}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;->register(Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;)Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    check-cast v5, Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;

    .line 100
    .line 101
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    const/4 p1, 0x1

    .line 110
    if-ne p0, p1, :cond_3

    .line 111
    .line 112
    const/4 p0, 0x0

    .line 113
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;

    .line 118
    .line 119
    return-object p0

    .line 120
    :cond_3
    new-instance p0, Lio/opentelemetry/sdk/metrics/SdkMeter$MultiWritableMetricStorage;

    .line 121
    .line 122
    const/4 p1, 0x0

    .line 123
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeter$MultiWritableMetricStorage;-><init>(Ljava/util/List;Lio/opentelemetry/sdk/metrics/SdkMeter$1;)V

    .line 124
    .line 125
    .line 126
    return-object p0
.end method

.method public removeCallback(Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackRegistrations:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public resetForTest()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->collectLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackLock:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    :try_start_1
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->callbackRegistrations:Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {v2}, Ljava/util/List;->clear()V

    .line 10
    .line 11
    .line 12
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 13
    :try_start_2
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    new-instance v1, Lio/opentelemetry/sdk/metrics/e;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-direct {v1, v2}, Lio/opentelemetry/sdk/metrics/e;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {p0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 26
    .line 27
    .line 28
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 29
    return-void

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    goto :goto_0

    .line 32
    :catchall_1
    move-exception p0

    .line 33
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 34
    :try_start_4
    throw p0

    .line 35
    :goto_0
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 36
    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SdkMeter{instrumentationScopeInfo="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, "}"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;
    .locals 1

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->checkValidInstrumentName(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->NOOP_METER:Lio/opentelemetry/api/metrics/Meter;

    .line 8
    .line 9
    const-string p1, "noop"

    .line 10
    .line 11
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-boolean v0, Lio/opentelemetry/sdk/metrics/SdkMeter;->INCUBATOR_AVAILABLE:Z

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/IncubatingUtil;->createExtendedLongUpDownCounterBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_1
    new-instance v0, Lio/opentelemetry/sdk/metrics/SdkLongUpDownCounter$SdkLongUpDownCounterBuilder;

    .line 26
    .line 27
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkLongUpDownCounter$SdkLongUpDownCounterBuilder;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public updateMeterConfig(Lio/opentelemetry/sdk/metrics/internal/MeterConfig;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/MeterConfig;->isEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 6
    .line 7
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 8
    .line 9
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 28
    .line 29
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->readerStorageRegistries:Ljava/util/Map;

    .line 30
    .line 31
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;

    .line 36
    .line 37
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorageRegistry;->getStorages()Ljava/util/Collection;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_0

    .line 53
    .line 54
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    check-cast v1, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;

    .line 59
    .line 60
    iget-boolean v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeter;->meterEnabled:Z

    .line 61
    .line 62
    invoke-interface {v1, v2}, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;->setEnabled(Z)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    return-void
.end method
