.class public Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;
    }
.end annotation


# static fields
.field private static final ATTRIBUTE_KEY_SUCCESS:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field private static final ATTRIBUTE_KEY_TYPE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private volatile exported:Lio/opentelemetry/api/metrics/LongCounter;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final exporterName:Ljava/lang/String;

.field private final failedAttrs:Lio/opentelemetry/api/common/Attributes;

.field private final meterProviderSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;"
        }
    .end annotation
.end field

.field private volatile seen:Lio/opentelemetry/api/metrics/LongCounter;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final seenAttrs:Lio/opentelemetry/api/common/Attributes;

.field private final successAttrs:Lio/opentelemetry/api/common/Attributes;

.field private final transportName:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "type"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->ATTRIBUTE_KEY_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "success"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->ATTRIBUTE_KEY_SUCCESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;",
            "Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 5
    .line 6
    invoke-static {p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->getExporterName(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exporterName:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->getTransportName(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->transportName:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->ATTRIBUTE_KEY_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 23
    .line 24
    invoke-virtual {p2}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->signal()Lio/opentelemetry/sdk/internal/Signal;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    invoke-static {p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->getTypeString(Lio/opentelemetry/sdk/internal/Signal;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p2

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
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->seenAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 41
    .line 42
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->ATTRIBUTE_KEY_SUCCESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 47
    .line 48
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-interface {p2, v0, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    invoke-interface {p2}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->successAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 59
    .line 60
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 65
    .line 66
    invoke-interface {p1, v0, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->failedAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 75
    .line 76
    return-void
.end method

.method public static synthetic access$100(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;J)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->addSeen(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$200(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;J)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->addFailed(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$300(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;J)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->addSuccess(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private addFailed(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exported()Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->failedAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/LongCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private addSeen(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->seen()Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->seenAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/LongCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private addSuccess(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exported()Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->successAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/LongCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private exported()Lio/opentelemetry/api/metrics/LongCounter;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exported:Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->isNoop(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object v0

    .line 13
    :cond_1
    :goto_0
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->meter()Lio/opentelemetry/api/metrics/Meter;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    new-instance v1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    .line 21
    .line 22
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exporterName:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v2, ".exporter.exported"

    .line 28
    .line 29
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/Meter;->counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongCounter;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exported:Lio/opentelemetry/api/metrics/LongCounter;

    .line 45
    .line 46
    return-object v0
.end method

.method private static getExporterName(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    new-instance v1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v2, "Not a supported exporter type: "

    .line 17
    .line 18
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw v0

    .line 32
    :pswitch_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string v0, "Profiles are not supported"

    .line 35
    .line 36
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :pswitch_1
    const-string p0, "zipkin"

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    const-string p0, "otlp"

    .line 44
    .line 45
    return-object p0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_0
    .end packed-switch
.end method

.method private static getTransportName(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    new-instance v1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v2, "Not a supported exporter type: "

    .line 17
    .line 18
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw v0

    .line 32
    :pswitch_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string v0, "Profiles are not supported"

    .line 35
    .line 36
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :pswitch_1
    const-string p0, "http-json"

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    const-string p0, "http"

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_3
    const-string p0, "grpc"

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_2
        :pswitch_1
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private static getTypeString(Lio/opentelemetry/sdk/internal/Signal;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$Signal:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_3

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_2

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq v0, v1, :cond_1

    .line 17
    .line 18
    const/4 v1, 0x4

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    new-instance v1, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v2, "Unhandled signal type: "

    .line 26
    .line 27
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw v0

    .line 41
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 42
    .line 43
    const-string v0, "Profiles are not supported"

    .line 44
    .line 45
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    const-string p0, "metric"

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_2
    const-string p0, "log"

    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_3
    const-string p0, "span"

    .line 56
    .line 57
    return-object p0
.end method

.method public static isSupportedType(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Z
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;->$SwitchMap$io$opentelemetry$sdk$internal$StandardComponentId$ExporterType:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    aget p0, v0, p0

    .line 8
    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :pswitch_0
    const/4 p0, 0x1

    .line 15
    return p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method private meter()Lio/opentelemetry/api/metrics/Meter;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lio/opentelemetry/api/metrics/MeterProvider;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v2, "io.opentelemetry.exporters."

    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exporterName:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v2, "-"

    .line 28
    .line 29
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->transportName:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {v0, p0}, Lio/opentelemetry/api/metrics/MeterProvider;->get(Ljava/lang/String;)Lio/opentelemetry/api/metrics/Meter;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method private seen()Lio/opentelemetry/api/metrics/LongCounter;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->seen:Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->isNoop(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object v0

    .line 13
    :cond_1
    :goto_0
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->meter()Lio/opentelemetry/api/metrics/Meter;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    new-instance v1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    .line 21
    .line 22
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->exporterName:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v2, ".exporter.seen"

    .line 28
    .line 29
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/Meter;->counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongCounter;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->seen:Lio/opentelemetry/api/metrics/LongCounter;

    .line 45
    .line 46
    return-object v0
.end method


# virtual methods
.method public startRecordingExport(I)Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, v1}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;-><init>(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;ILio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method
