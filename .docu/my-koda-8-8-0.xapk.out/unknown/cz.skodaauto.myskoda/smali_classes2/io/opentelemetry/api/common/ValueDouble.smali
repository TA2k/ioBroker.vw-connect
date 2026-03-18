.class final Lio/opentelemetry/api/common/ValueDouble;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/common/Value;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/api/common/Value<",
        "Ljava/lang/Double;",
        ">;"
    }
.end annotation


# instance fields
.field private final value:D


# direct methods
.method private constructor <init>(D)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lio/opentelemetry/api/common/ValueDouble;->value:D

    .line 5
    .line 6
    return-void
.end method

.method public static create(D)Lio/opentelemetry/api/common/Value;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(D)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/common/ValueDouble;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/api/common/ValueDouble;-><init>(D)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public asString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/api/common/ValueDouble;->value:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/api/common/Value;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    iget-wide v1, p0, Lio/opentelemetry/api/common/ValueDouble;->value:D

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p1, Lio/opentelemetry/api/common/Value;

    .line 16
    .line 17
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    return v0

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public getType()Lio/opentelemetry/api/common/ValueType;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/common/ValueType;->DOUBLE:Lio/opentelemetry/api/common/ValueType;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValue()Ljava/lang/Double;
    .locals 2

    .line 2
    iget-wide v0, p0, Lio/opentelemetry/api/common/ValueDouble;->value:D

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/api/common/ValueDouble;->getValue()Ljava/lang/Double;

    move-result-object p0

    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/api/common/ValueDouble;->value:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ValueDouble{"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/api/common/ValueDouble;->asString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v1, "}"

    .line 13
    .line 14
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
