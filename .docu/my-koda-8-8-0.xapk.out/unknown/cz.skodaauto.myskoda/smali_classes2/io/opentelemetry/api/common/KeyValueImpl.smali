.class abstract Lio/opentelemetry/api/common/KeyValueImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/common/KeyValue;


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

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/common/KeyValueImpl;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/api/common/KeyValueImpl;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/common/AutoValue_KeyValueImpl;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/api/common/AutoValue_KeyValueImpl;-><init>(Ljava/lang/String;Lio/opentelemetry/api/common/Value;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
