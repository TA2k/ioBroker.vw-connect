.class public interface abstract Lio/opentelemetry/api/common/Value;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# direct methods
.method public static of(D)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(D)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation

    .line 4
    invoke-static {p0, p1}, Lio/opentelemetry/api/common/ValueDouble;->create(D)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static of(J)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 3
    invoke-static {p0, p1}, Lio/opentelemetry/api/common/ValueLong;->create(J)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static of(Ljava/lang/String;)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/common/ValueString;->create(Ljava/lang/String;)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static of(Ljava/util/List;)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/Value<",
            "*>;>;)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/Value<",
            "*>;>;>;"
        }
    .end annotation

    .line 7
    invoke-static {p0}, Lio/opentelemetry/api/common/ValueArray;->create(Ljava/util/List;)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static of(Ljava/util/Map;)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;>;)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/KeyValue;",
            ">;>;"
        }
    .end annotation

    .line 9
    invoke-static {p0}, Lio/opentelemetry/api/common/KeyValueList;->createFromMap(Ljava/util/Map;)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static of(Z)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation

    .line 2
    invoke-static {p0}, Lio/opentelemetry/api/common/ValueBoolean;->create(Z)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static of([B)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([B)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/nio/ByteBuffer;",
            ">;"
        }
    .end annotation

    .line 5
    invoke-static {p0}, Lio/opentelemetry/api/common/ValueBytes;->create([B)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static varargs of([Lio/opentelemetry/api/common/KeyValue;)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Lio/opentelemetry/api/common/KeyValue;",
            ")",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/KeyValue;",
            ">;>;"
        }
    .end annotation

    .line 8
    invoke-static {p0}, Lio/opentelemetry/api/common/KeyValueList;->create([Lio/opentelemetry/api/common/KeyValue;)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method

.method public static varargs of([Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/api/common/Value<",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/Value<",
            "*>;>;>;"
        }
    .end annotation

    .line 6
    invoke-static {p0}, Lio/opentelemetry/api/common/ValueArray;->create([Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/common/Value;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public abstract asString()Ljava/lang/String;
.end method

.method public abstract getType()Lio/opentelemetry/api/common/ValueType;
.end method

.method public abstract getValue()Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation
.end method
