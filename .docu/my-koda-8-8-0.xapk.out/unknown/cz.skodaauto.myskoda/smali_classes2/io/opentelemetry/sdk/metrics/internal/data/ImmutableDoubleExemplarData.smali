.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableDoubleExemplarData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;


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

.method public static create(Lio/opentelemetry/api/common/Attributes;JLio/opentelemetry/api/trace/SpanContext;D)Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;
    .locals 7

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableDoubleExemplarData;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-wide v2, p1

    .line 5
    move-object v4, p3

    .line 6
    move-wide v5, p4

    .line 7
    invoke-direct/range {v0 .. v6}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableDoubleExemplarData;-><init>(Lio/opentelemetry/api/common/Attributes;JLio/opentelemetry/api/trace/SpanContext;D)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
