.class Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/logs/ExtendedLogger;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;
    }
.end annotation


# static fields
.field private static final INSTANCE:Lio/opentelemetry/api/logs/Logger;

.field private static final NOOP_LOG_RECORD_BUILDER:Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;->INSTANCE:Lio/opentelemetry/api/logs/Logger;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$NoopExtendedLogRecordBuilder;-><init>(Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger$1;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;->NOOP_LOG_RECORD_BUILDER:Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getNoop()Lio/opentelemetry/api/logs/Logger;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;->INSTANCE:Lio/opentelemetry/api/logs/Logger;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public isEnabled(Lio/opentelemetry/api/logs/Severity;Lio/opentelemetry/context/Context;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public logRecordBuilder()Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;
    .locals 0

    .line 2
    sget-object p0, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;->NOOP_LOG_RECORD_BUILDER:Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    return-object p0
.end method

.method public bridge synthetic logRecordBuilder()Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/api/incubator/logs/ExtendedDefaultLogger;->logRecordBuilder()Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    move-result-object p0

    return-object p0
.end method
