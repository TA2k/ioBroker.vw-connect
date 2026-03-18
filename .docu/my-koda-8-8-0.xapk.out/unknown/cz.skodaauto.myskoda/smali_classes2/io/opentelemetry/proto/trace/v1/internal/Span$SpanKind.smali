.class public final Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/proto/trace/v1/internal/Span;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "SpanKind"
.end annotation


# static fields
.field public static final SPAN_KIND_CLIENT:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final SPAN_KIND_CONSUMER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final SPAN_KIND_INTERNAL:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final SPAN_KIND_PRODUCER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final SPAN_KIND_SERVER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final SPAN_KIND_UNSPECIFIED:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const-string v1, "SPAN_KIND_UNSPECIFIED"

    .line 3
    .line 4
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_UNSPECIFIED:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    const-string v1, "SPAN_KIND_INTERNAL"

    .line 12
    .line 13
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_INTERNAL:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    const-string v1, "SPAN_KIND_SERVER"

    .line 21
    .line 22
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_SERVER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    const-string v1, "SPAN_KIND_CLIENT"

    .line 30
    .line 31
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_CLIENT:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 36
    .line 37
    const/4 v0, 0x4

    .line 38
    const-string v1, "SPAN_KIND_PRODUCER"

    .line 39
    .line 40
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_PRODUCER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 45
    .line 46
    const/4 v0, 0x5

    .line 47
    const-string v1, "SPAN_KIND_CONSUMER"

    .line 48
    .line 49
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Span$SpanKind;->SPAN_KIND_CONSUMER:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 54
    .line 55
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
