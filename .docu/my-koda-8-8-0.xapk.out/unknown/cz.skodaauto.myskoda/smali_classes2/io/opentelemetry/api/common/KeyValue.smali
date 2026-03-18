.class public interface abstract Lio/opentelemetry/api/common/KeyValue;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static of(Ljava/lang/String;Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/common/KeyValue;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/api/common/KeyValue;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/api/common/KeyValueImpl;->create(Ljava/lang/String;Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/common/KeyValueImpl;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getKey()Ljava/lang/String;
.end method

.method public abstract getValue()Lio/opentelemetry/api/common/Value;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation
.end method
