.class Lio/opentelemetry/api/logs/DefaultLogger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/Logger;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/logs/DefaultLogger$NoopLogRecordBuilder;
    }
.end annotation


# static fields
.field private static final INSTANCE:Lio/opentelemetry/api/logs/Logger;

.field private static final NOOP_LOG_RECORD_BUILDER:Lio/opentelemetry/api/logs/LogRecordBuilder;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/logs/DefaultLogger;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/logs/DefaultLogger;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/api/logs/DefaultLogger;->INSTANCE:Lio/opentelemetry/api/logs/Logger;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/api/logs/DefaultLogger$NoopLogRecordBuilder;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/api/logs/DefaultLogger$NoopLogRecordBuilder;-><init>(Lio/opentelemetry/api/logs/DefaultLogger$1;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/logs/DefaultLogger;->NOOP_LOG_RECORD_BUILDER:Lio/opentelemetry/api/logs/LogRecordBuilder;

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

.method public static getInstance()Lio/opentelemetry/api/logs/Logger;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/logs/DefaultLogger;->INSTANCE:Lio/opentelemetry/api/logs/Logger;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public logRecordBuilder()Lio/opentelemetry/api/logs/LogRecordBuilder;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/api/logs/DefaultLogger;->NOOP_LOG_RECORD_BUILDER:Lio/opentelemetry/api/logs/LogRecordBuilder;

    .line 2
    .line 3
    return-object p0
.end method
