.class Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/MeterProvider;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/OpenTelemetrySdk;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ObfuscatedMeterProvider"
.end annotation

.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field private final delegate:Lio/opentelemetry/sdk/metrics/SdkMeterProvider;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/SdkMeterProvider;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;->delegate:Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;->delegate:Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider;->meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public unobfuscate()Lio/opentelemetry/sdk/metrics/SdkMeterProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/OpenTelemetrySdk$ObfuscatedMeterProvider;->delegate:Lio/opentelemetry/sdk/metrics/SdkMeterProvider;

    .line 2
    .line 3
    return-object p0
.end method
