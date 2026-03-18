.class Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongHistogram;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/LongHistogram;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/metrics/DefaultMeter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoopLongHistogram"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/metrics/DefaultMeter$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/api/metrics/DefaultMeter$NoopLongHistogram;-><init>()V

    return-void
.end method


# virtual methods
.method public record(J)V
    .locals 0

    .line 1
    return-void
.end method

.method public record(JLio/opentelemetry/api/common/Attributes;)V
    .locals 0

    .line 2
    return-void
.end method

.method public record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 3
    return-void
.end method
