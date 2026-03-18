.class final Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "NoopExtendedLogRecordBuilder"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;-><init>()V

    return-void
.end method


# virtual methods
.method public emit()V
    .locals 0

    .line 1
    return-void
.end method

.method public setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
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
            "Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public setAttribute(Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey<",
            "TT;>;TT;)",
            "Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;"
        }
    .end annotation

    .line 2
    return-object p0
.end method

.method public bridge synthetic setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setAttribute(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Value<",
            "*>;)",
            "Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;"
        }
    .end annotation

    .line 1
    return-object p0
.end method

.method public setBody(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public bridge synthetic setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setBody(Lio/opentelemetry/api/common/Value;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setBody(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 4
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setBody(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setEventName(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setEventName(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setEventName(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setException(Ljava/lang/Throwable;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public bridge synthetic setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setObservedTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 4
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setObservedTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setSeverity(Lio/opentelemetry/api/logs/Severity;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public bridge synthetic setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setSeverityText(Ljava/lang/String;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 1
    return-object p0
.end method

.method public setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 2
    return-object p0
.end method

.method public bridge synthetic setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setTimestamp(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 4
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;->setTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method
