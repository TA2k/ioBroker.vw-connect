.class abstract Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/data/internal/ExtendedLogRecordData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


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

.method public static create(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Ljava/lang/String;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/api/incubator/common/ExtendedAttributes;I)Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordData;
    .locals 14
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p10    # Lio/opentelemetry/api/common/Value;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/lang/String;",
            "JJ",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/api/logs/Severity;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/api/incubator/common/ExtendedAttributes;",
            "I)",
            "Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordData;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/AutoValue_ExtendedSdkLogRecordData;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object v2, p1

    .line 5
    move-object/from16 v13, p2

    .line 6
    .line 7
    move-wide/from16 v3, p3

    .line 8
    .line 9
    move-wide/from16 v5, p5

    .line 10
    .line 11
    move-object/from16 v7, p7

    .line 12
    .line 13
    move-object/from16 v8, p8

    .line 14
    .line 15
    move-object/from16 v9, p9

    .line 16
    .line 17
    move-object/from16 v12, p10

    .line 18
    .line 19
    move-object/from16 v11, p11

    .line 20
    .line 21
    move/from16 v10, p12

    .line 22
    .line 23
    invoke-direct/range {v0 .. v13}, Lio/opentelemetry/sdk/logs/AutoValue_ExtendedSdkLogRecordData;-><init>(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;ILio/opentelemetry/api/incubator/common/ExtendedAttributes;Lio/opentelemetry/api/common/Value;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method


# virtual methods
.method public getBody()Lio/opentelemetry/sdk/logs/data/Body;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/ExtendedSdkLogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/sdk/logs/data/Body;->empty()Lio/opentelemetry/sdk/logs/data/Body;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-interface {p0}, Lio/opentelemetry/api/common/Value;->asString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/data/Body;->string(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/data/Body;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public abstract getBodyValue()Lio/opentelemetry/api/common/Value;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getEventName()Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method
