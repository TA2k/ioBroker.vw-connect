.class public final Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private instrumentName:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private instrumentType:Lio/opentelemetry/sdk/metrics/InstrumentType;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private instrumentUnit:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private meterName:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private meterSchemaUrl:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private meterVersion:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/sdk/metrics/InstrumentSelector;
    .locals 8

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentType:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentName:Ljava/lang/String;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentUnit:Ljava/lang/String;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterName:Ljava/lang/String;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterVersion:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterSchemaUrl:Ljava/lang/String;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x0

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    :goto_0
    const/4 v0, 0x1

    .line 29
    :goto_1
    const-string v1, "Instrument selector must contain selection criteria"

    .line 30
    .line 31
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentType:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 35
    .line 36
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentName:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentUnit:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v5, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterName:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v6, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterVersion:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v7, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterSchemaUrl:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static/range {v2 .. v7}, Lio/opentelemetry/sdk/metrics/InstrumentSelector;->create(Lio/opentelemetry/sdk/metrics/InstrumentType;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public setMeterName(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
    .locals 1

    .line 1
    const-string v0, "meterName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterName:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public setMeterSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
    .locals 1

    .line 1
    const-string v0, "meterSchemaUrl"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterSchemaUrl:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public setMeterVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
    .locals 1

    .line 1
    const-string v0, "meterVersion"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->meterVersion:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public setName(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentName:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public setType(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
    .locals 1

    .line 1
    const-string v0, "instrumentType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentType:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 7
    .line 8
    return-object p0
.end method

.method public setUnit(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;
    .locals 1

    .line 1
    const-string v0, "unit"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/InstrumentSelectorBuilder;->instrumentUnit:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method
