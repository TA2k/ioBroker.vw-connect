.class public abstract Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.super Lio/opentelemetry/exporter/internal/marshal/Marshaler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final size:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;->size:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final getBinarySerializedSize()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;->size:I

    .line 2
    .line 3
    return p0
.end method
