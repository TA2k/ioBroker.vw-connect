.class Lio/opentelemetry/api/metrics/DefaultMeterProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/MeterProvider;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/metrics/DefaultMeterProvider$NoopMeterBuilder;
    }
.end annotation


# static fields
.field private static final BUILDER_INSTANCE:Lio/opentelemetry/api/metrics/MeterBuilder;

.field private static final INSTANCE:Lio/opentelemetry/api/metrics/MeterProvider;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeterProvider;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/metrics/DefaultMeterProvider;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "io.opentelemetry.api.incubator.metrics.ExtendedDefaultMeterProvider"

    .line 7
    .line 8
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/IncubatingUtil;->incubatingApiIfAvailable(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lio/opentelemetry/api/metrics/MeterProvider;

    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeterProvider;->INSTANCE:Lio/opentelemetry/api/metrics/MeterProvider;

    .line 15
    .line 16
    new-instance v0, Lio/opentelemetry/api/metrics/DefaultMeterProvider$NoopMeterBuilder;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-direct {v0, v1}, Lio/opentelemetry/api/metrics/DefaultMeterProvider$NoopMeterBuilder;-><init>(Lio/opentelemetry/api/metrics/DefaultMeterProvider$1;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lio/opentelemetry/api/metrics/DefaultMeterProvider;->BUILDER_INSTANCE:Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 23
    .line 24
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

.method public static getInstance()Lio/opentelemetry/api/metrics/MeterProvider;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/metrics/DefaultMeterProvider;->INSTANCE:Lio/opentelemetry/api/metrics/MeterProvider;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/metrics/DefaultMeterProvider;->BUILDER_INSTANCE:Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 2
    .line 3
    return-object p0
.end method
