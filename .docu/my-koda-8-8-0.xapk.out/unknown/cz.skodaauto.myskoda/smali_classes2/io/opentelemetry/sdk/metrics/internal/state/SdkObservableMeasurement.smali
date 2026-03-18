.class public final Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/ObservableLongMeasurement;
.implements Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private volatile activeReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final instrumentDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private final storages:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage<",
            "*>;>;"
        }
    .end annotation
.end field

.field private final throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

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
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage<",
            "*>;>;)V"
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
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->logger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 14
    .line 15
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->instrumentDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 16
    .line 17
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->storages:Ljava/util/List;

    .line 18
    .line 19
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage<",
            "*>;>;)",
            "Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;-><init>(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Ljava/util/List;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private logNoActiveReader()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->throttlingLogger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 2
    .line 3
    sget-object v1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 4
    .line 5
    new-instance v2, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v3, "Measurement recorded for instrument "

    .line 8
    .line 9
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->instrumentDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 13
    .line 14
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, " outside callback registered to instrument. Dropping measurement."

    .line 22
    .line 23
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {v0, v1, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public getInstrumentDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->instrumentDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStorages()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage<",
            "*>;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->storages:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public record(D)V
    .locals 1

    .line 7
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-virtual {p0, p1, p2, v0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->record(DLio/opentelemetry/api/common/Attributes;)V

    return-void
.end method

.method public record(DLio/opentelemetry/api/common/Attributes;)V
    .locals 3

    .line 8
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->activeReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    if-nez v0, :cond_0

    .line 9
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->logNoActiveReader()V

    return-void

    .line 10
    :cond_0
    invoke-static {p1, p2}, Ljava/lang/Double;->isNaN(D)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 11
    sget-object p1, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->logger:Ljava/util/logging/Logger;

    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Instrument "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->instrumentDescriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 12
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, " has recorded measurement Not-a-Number (NaN) value with attributes "

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, ". Dropping measurement."

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 13
    invoke-virtual {p1, p2, p0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    return-void

    .line 14
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->storages:Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_2
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 15
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->getRegisteredReader()Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    move-result-object v2

    invoke-virtual {v2, v0}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    .line 16
    invoke-virtual {v1, p3, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->record(Lio/opentelemetry/api/common/Attributes;D)V

    goto :goto_0

    :cond_3
    return-void
.end method

.method public record(J)V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-virtual {p0, p1, p2, v0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->record(JLio/opentelemetry/api/common/Attributes;)V

    return-void
.end method

.method public record(JLio/opentelemetry/api/common/Attributes;)V
    .locals 3

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->activeReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    if-nez v0, :cond_0

    .line 3
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->logNoActiveReader()V

    return-void

    .line 4
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->storages:Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->getRegisteredReader()Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    move-result-object v2

    invoke-virtual {v2, v0}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    .line 6
    invoke-virtual {v1, p3, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->record(Lio/opentelemetry/api/common/Attributes;J)V

    goto :goto_0

    :cond_2
    return-void
.end method

.method public setActiveReader(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;JJ)V
    .locals 3

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->activeReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 2
    .line 3
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->storages:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;

    .line 20
    .line 21
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->getRegisteredReader()Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->activeReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 26
    .line 27
    invoke-virtual {v1, v2}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    invoke-virtual {v0, p2, p3, p4, p5}, Lio/opentelemetry/sdk/metrics/internal/state/AsynchronousMetricStorage;->setEpochInformation(JJ)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    return-void
.end method

.method public unsetActiveReader()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;->activeReader:Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 3
    .line 4
    return-void
.end method
