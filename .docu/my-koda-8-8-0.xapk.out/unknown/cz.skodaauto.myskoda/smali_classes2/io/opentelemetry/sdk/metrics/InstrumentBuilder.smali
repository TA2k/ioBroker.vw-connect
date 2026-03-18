.class final Lio/opentelemetry/sdk/metrics/InstrumentBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SwapBuilder;,
        Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SynchronousInstrumentConstructor;
    }
.end annotation


# instance fields
.field private adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

.field private description:Ljava/lang/String;

.field private final name:Ljava/lang/String;

.field private final sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

.field private type:Lio/opentelemetry/sdk/metrics/InstrumentType;

.field private unit:Ljava/lang/String;

.field private final valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lio/opentelemetry/sdk/metrics/InstrumentType;Lio/opentelemetry/sdk/metrics/InstrumentValueType;Lio/opentelemetry/sdk/metrics/SdkMeter;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;->builder()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 9
    .line 10
    const-string v0, ""

    .line 11
    .line 12
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->description:Ljava/lang/String;

    .line 13
    .line 14
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->unit:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->name:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->type:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 19
    .line 20
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;

    .line 21
    .line 22
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 23
    .line 24
    return-void
.end method

.method public static synthetic a(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->lambda$buildLongAsynchronousInstrument$1(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->lambda$buildDoubleAsynchronousInstrument$0(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$buildDoubleAsynchronousInstrument$0(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static synthetic lambda$buildLongAsynchronousInstrument$1(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;)V
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private newDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;
    .locals 6

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->name:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->description:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->unit:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->type:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 8
    .line 9
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 12
    .line 13
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;->build()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    invoke-static/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/InstrumentType;Lio/opentelemetry/sdk/metrics/InstrumentValueType;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;)Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method


# virtual methods
.method public buildDoubleAsynchronousInstrument(Lio/opentelemetry/sdk/metrics/InstrumentType;Ljava/util/function/Consumer;)Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/InstrumentType;",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableDoubleMeasurement;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->buildObservableMeasurement(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Lio/opentelemetry/sdk/metrics/b;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p2, p1, v1}, Lio/opentelemetry/sdk/metrics/b;-><init>(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-static {p1, v0}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->create(Ljava/util/List;Ljava/lang/Runnable;)Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 20
    .line 21
    invoke-virtual {p2, p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->registerCallback(Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 22
    .line 23
    .line 24
    new-instance p2, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;

    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 27
    .line 28
    invoke-direct {p2, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 29
    .line 30
    .line 31
    return-object p2
.end method

.method public buildLongAsynchronousInstrument(Lio/opentelemetry/sdk/metrics/InstrumentType;Ljava/util/function/Consumer;)Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/metrics/InstrumentType;",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/api/metrics/ObservableLongMeasurement;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->buildObservableMeasurement(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Lio/opentelemetry/sdk/metrics/b;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p2, p1, v1}, Lio/opentelemetry/sdk/metrics/b;-><init>(Ljava/util/function/Consumer;Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-static {p1, v0}, Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;->create(Ljava/util/List;Ljava/lang/Runnable;)Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iget-object p2, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 20
    .line 21
    invoke-virtual {p2, p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->registerCallback(Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 22
    .line 23
    .line 24
    new-instance p2, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;

    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 27
    .line 28
    invoke-direct {p2, p0, p1}, Lio/opentelemetry/sdk/metrics/SdkObservableInstrument;-><init>(Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/CallbackRegistration;)V

    .line 29
    .line 30
    .line 31
    return-object p2
.end method

.method public buildObservableMeasurement(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->type:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 2
    .line 3
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->newDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeter;->registerObservableMeasurement(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/state/SdkObservableMeasurement;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public buildSynchronousInstrument(Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SynchronousInstrumentConstructor;)Lio/opentelemetry/sdk/metrics/AbstractInstrument;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<I:",
            "Lio/opentelemetry/sdk/metrics/AbstractInstrument;",
            ">(",
            "Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SynchronousInstrumentConstructor<",
            "TI;>;)TI;"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->newDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Lio/opentelemetry/sdk/metrics/SdkMeter;->registerSynchronousMetricStorage(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 12
    .line 13
    invoke-interface {p1, v0, p0, v1}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SynchronousInstrumentConstructor;->createInstrument(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/SdkMeter;Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;)Lio/opentelemetry/sdk/metrics/AbstractInstrument;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public setAdviceAttributes(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;->setAttributes(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setAdviceBuilder(Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)Lio/opentelemetry/sdk/metrics/InstrumentBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public setDescription(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public setExplicitBucketBoundaries(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;->setExplicitBucketBoundaries(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->unit:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public swapBuilder(Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SwapBuilder;)Ljava/lang/Object;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SwapBuilder<",
            "TT;>;)TT;"
        }
    .end annotation

    .line 1
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->sdkMeter:Lio/opentelemetry/sdk/metrics/SdkMeter;

    .line 2
    .line 3
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->name:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->description:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->unit:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v5, p0, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->adviceBuilder:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 10
    .line 11
    move-object v0, p1

    .line 12
    invoke-interface/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder$SwapBuilder;->newBuilder(Lio/opentelemetry/sdk/metrics/SdkMeter;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "InstrumentBuilder"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->toStringHelper(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public toStringHelper(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "{descriptor="

    .line 2
    .line 3
    invoke-static {p1, v0}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/InstrumentBuilder;->newDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    const-string p0, "}"

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
