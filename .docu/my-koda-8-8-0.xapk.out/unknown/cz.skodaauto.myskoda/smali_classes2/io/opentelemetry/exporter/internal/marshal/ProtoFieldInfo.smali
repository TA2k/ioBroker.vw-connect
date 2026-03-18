.class public abstract Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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

.method public static create(IILjava/lang/String;)Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeTagSize(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-direct {v0, p0, p1, v1, p2}, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;-><init>(IIILjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public abstract getFieldNumber()I
.end method

.method public abstract getJsonName()Ljava/lang/String;
.end method

.method public abstract getTag()I
.end method

.method public abstract getTagSize()I
.end method
