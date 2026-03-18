.class final Lio/opentelemetry/api/logs/DefaultLogger$NoopLogRecordBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/LogRecordBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/logs/DefaultLogger;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "NoopLogRecordBuilder"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/logs/DefaultLogger$1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/api/logs/DefaultLogger$NoopLogRecordBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public emit()V
    .locals 0

    .line 1
    return-void
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/logs/LogRecordBuilder;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/api/logs/LogRecordBuilder;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public setBody(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    return-object p0
.end method
