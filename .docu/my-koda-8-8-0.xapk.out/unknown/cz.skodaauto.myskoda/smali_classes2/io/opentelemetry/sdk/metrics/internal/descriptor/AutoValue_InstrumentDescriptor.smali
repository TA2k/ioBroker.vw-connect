.class final Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;
.super Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final advice:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

.field private final description:Ljava/lang/String;

.field private final name:Ljava/lang/String;

.field private final type:Lio/opentelemetry/sdk/metrics/InstrumentType;

.field private final unit:Ljava/lang/String;

.field private final valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/InstrumentType;Lio/opentelemetry/sdk/metrics/InstrumentValueType;Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_5

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->name:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p2, :cond_4

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->description:Ljava/lang/String;

    .line 11
    .line 12
    if-eqz p3, :cond_3

    .line 13
    .line 14
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->unit:Ljava/lang/String;

    .line 15
    .line 16
    if-eqz p4, :cond_2

    .line 17
    .line 18
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->type:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 19
    .line 20
    if-eqz p5, :cond_1

    .line 21
    .line 22
    iput-object p5, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;

    .line 23
    .line 24
    if-eqz p6, :cond_0

    .line 25
    .line 26
    iput-object p6, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->advice:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 30
    .line 31
    const-string p1, "Null advice"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 38
    .line 39
    const-string p1, "Null valueType"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 46
    .line 47
    const-string p1, "Null type"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 54
    .line 55
    const-string p1, "Null unit"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    .line 62
    .line 63
    const-string p1, "Null description"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_5
    new-instance p0, Ljava/lang/NullPointerException;

    .line 70
    .line 71
    const-string p1, "Null name"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0
.end method


# virtual methods
.method public getAdvice()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->advice:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDescription()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getType()Lio/opentelemetry/sdk/metrics/InstrumentType;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->type:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 2
    .line 3
    return-object p0
.end method

.method public getUnit()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->unit:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValueType()Lio/opentelemetry/sdk/metrics/InstrumentValueType;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "InstrumentDescriptor{name="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->name:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", description="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->description:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", unit="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->unit:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", type="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->type:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", valueType="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->valueType:Lio/opentelemetry/sdk/metrics/InstrumentValueType;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", advice="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_InstrumentDescriptor;->advice:Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;

    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, "}"

    .line 64
    .line 65
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method
