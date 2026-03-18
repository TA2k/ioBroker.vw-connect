.class public final Lio/opentelemetry/proto/profiles/v1development/internal/Mapping;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ATTRIBUTE_INDICES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final FILENAME_STRINDEX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final FILE_OFFSET:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final MEMORY_LIMIT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public static final MEMORY_START:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    const-string v1, "memoryStart"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Mapping;->MEMORY_START:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    const/16 v0, 0x10

    .line 13
    .line 14
    const-string v1, "memoryLimit"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Mapping;->MEMORY_LIMIT:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 22
    .line 23
    const/16 v0, 0x18

    .line 24
    .line 25
    const-string v1, "fileOffset"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Mapping;->FILE_OFFSET:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 33
    .line 34
    const/16 v0, 0x20

    .line 35
    .line 36
    const-string v1, "filenameStrindex"

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
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Mapping;->FILENAME_STRINDEX:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 44
    .line 45
    const/16 v0, 0x2a

    .line 46
    .line 47
    const-string v1, "attributeIndices"

    .line 48
    .line 49
    const/4 v2, 0x5

    .line 50
    invoke-static {v2, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lio/opentelemetry/proto/profiles/v1development/internal/Mapping;->ATTRIBUTE_INDICES:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 55
    .line 56
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
