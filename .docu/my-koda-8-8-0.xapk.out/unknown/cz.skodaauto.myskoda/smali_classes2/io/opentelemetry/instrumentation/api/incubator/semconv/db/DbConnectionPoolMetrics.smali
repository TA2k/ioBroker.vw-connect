.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final CONNECTION_STATE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final POOL_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final STATE_IDLE:Ljava/lang/String; = "idle"

.field static final STATE_USED:Ljava/lang/String; = "used"


# instance fields
.field private final attributes:Lio/opentelemetry/api/common/Attributes;

.field private final idleConnectionsAttributes:Lio/opentelemetry/api/common/Attributes;

.field private final meter:Lio/opentelemetry/api/metrics/Meter;

.field private final usedConnectionsAttributes:Lio/opentelemetry/api/common/Attributes;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.pool.name"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "pool.name"

    .line 11
    .line 12
    :goto_0
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->POOL_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "db.client.connection.state"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "state"

    .line 28
    .line 29
    :goto_1
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->CONNECTION_STATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 34
    .line 35
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/api/metrics/Meter;Lio/opentelemetry/api/common/Attributes;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 7
    .line 8
    invoke-interface {p2}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->CONNECTION_STATE:Lio/opentelemetry/api/common/AttributeKey;

    .line 13
    .line 14
    const-string v1, "used"

    .line 15
    .line 16
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->usedConnectionsAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 25
    .line 26
    invoke-interface {p2}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    const-string p2, "idle"

    .line 31
    .line 32
    invoke-interface {p1, v0, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->idleConnectionsAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 41
    .line 42
    return-void
.end method

.method public static create(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;
    .locals 1

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/OpenTelemetry;->getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/MeterProvider;->meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->findVersion(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lio/opentelemetry/api/metrics/MeterBuilder;->setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 16
    .line 17
    .line 18
    :cond_0
    new-instance p1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;

    .line 19
    .line 20
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/MeterBuilder;->build()Lio/opentelemetry/api/metrics/Meter;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->POOL_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 25
    .line 26
    invoke-static {v0, p2}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    .line 27
    .line 28
    .line 29
    move-result-object p2

    .line 30
    invoke-direct {p1, p0, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;-><init>(Lio/opentelemetry/api/metrics/Meter;Lio/opentelemetry/api/common/Attributes;)V

    .line 31
    .line 32
    .line 33
    return-object p1
.end method


# virtual methods
.method public varargs batchCallback(Ljava/lang/Runnable;Lio/opentelemetry/api/metrics/ObservableMeasurement;[Lio/opentelemetry/api/metrics/ObservableMeasurement;)Lio/opentelemetry/api/metrics/BatchCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3}, Lio/opentelemetry/api/metrics/Meter;->batchCallback(Ljava/lang/Runnable;Lio/opentelemetry/api/metrics/ObservableMeasurement;[Lio/opentelemetry/api/metrics/ObservableMeasurement;)Lio/opentelemetry/api/metrics/BatchCallback;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public connectionCreateTime()Lio/opentelemetry/api/metrics/DoubleHistogram;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.create_time"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.create_time"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "s"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "ms"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The time it took to create a new connection."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->build()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public connectionTimeouts()Lio/opentelemetry/api/metrics/LongCounter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.timeouts"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.timeouts"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "{timeout}"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "{timeouts}"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The number of connection timeouts that have occurred trying to obtain a connection from the pool."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongCounter;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public connectionUseTime()Lio/opentelemetry/api/metrics/DoubleHistogram;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.use_time"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.use_time"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "s"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "ms"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The time between borrowing a connection and returning it to the pool."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->build()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public connectionWaitTime()Lio/opentelemetry/api/metrics/DoubleHistogram;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.wait_time"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.wait_time"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "s"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "ms"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The time it took to obtain an open connection from the pool."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->build()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public connections()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.count"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.usage"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "{connection}"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "{connections}"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The number of connections that are currently in state described by the state attribute."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdleConnectionsAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->idleConnectionsAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUsedConnectionsAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->usedConnectionsAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public maxConnections()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.max"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.max"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "{connection}"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "{connections}"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The maximum number of open connections allowed."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public maxIdleConnections()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.idle.max"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.idle.max"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "{connection}"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "{connections}"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The maximum number of idle open connections allowed."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public minIdleConnections()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.idle.min"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.idle.min"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "{connection}"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "{connections}"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "The minimum number of idle open connections allowed."

    .line 34
    .line 35
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public pendingRequestsForConnection()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string v0, "db.client.connection.pending_requests"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "db.client.connections.pending_requests"

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbConnectionPoolMetrics;->meter:Lio/opentelemetry/api/metrics/Meter;

    .line 13
    .line 14
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    const-string v0, "{request}"

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const-string v0, "{requests}"

    .line 28
    .line 29
    :goto_1
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    const-string v0, "The number of current pending requests for an open connection."

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const-string v0, "The number of pending requests for an open connection, cumulative for the entire pool."

    .line 43
    .line 44
    :goto_2
    invoke-interface {p0, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-interface {p0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->buildObserver()Lio/opentelemetry/api/metrics/ObservableLongMeasurement;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
