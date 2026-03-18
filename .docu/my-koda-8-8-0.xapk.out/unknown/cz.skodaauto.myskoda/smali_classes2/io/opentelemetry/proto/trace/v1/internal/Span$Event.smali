.class public final Lio/opentelemetry/proto/trace/v1/internal/Span$Event;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/proto/trace/v1/internal/Span;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Event"
.end annotation


# static fields
.field public static final ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    const-string v1, "timeUnixNano"

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->TIME_UNIX_NANO:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x12

    .line 13
    .line 14
    const-string v1, "name"

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->NAME:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    const/16 v0, 0x1a

    .line 24
    .line 25
    const-string v1, "attributes"

    .line 26
    .line 27
    const/4 v2, 0x3

    .line 28
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->ATTRIBUTES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x20

    .line 35
    .line 36
    const-string v1, "droppedAttributesCount"

    .line 37
    .line 38
    const/4 v2, 0x4

    .line 39
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$Event;->DROPPED_ATTRIBUTES_COUNT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
