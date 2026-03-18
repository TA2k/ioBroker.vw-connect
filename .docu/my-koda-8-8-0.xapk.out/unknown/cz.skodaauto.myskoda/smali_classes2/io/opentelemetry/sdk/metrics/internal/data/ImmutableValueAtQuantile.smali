.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableValueAtQuantile;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;


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

.method public static create(DD)Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableValueAtQuantile;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableValueAtQuantile;-><init>(DD)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
