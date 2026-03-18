.class public final Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/proto/trace/v1/internal/Status;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "StatusCode"
.end annotation


# static fields
.field public static final STATUS_CODE_ERROR:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final STATUS_CODE_OK:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

.field public static final STATUS_CODE_UNSET:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const-string v1, "STATUS_CODE_UNSET"

    .line 3
    .line 4
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;->STATUS_CODE_UNSET:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    const-string v1, "STATUS_CODE_OK"

    .line 12
    .line 13
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;->STATUS_CODE_OK:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    const-string v1, "STATUS_CODE_ERROR"

    .line 21
    .line 22
    invoke-static {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sput-object v0, Lio/opentelemetry/proto/trace/v1/internal/Status$StatusCode;->STATUS_CODE_ERROR:Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;

    .line 27
    .line 28
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
