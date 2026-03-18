.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableDoublePointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/DoublePointData;


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

.method public static create(JJLio/opentelemetry/api/common/Attributes;D)Lio/opentelemetry/sdk/metrics/data/DoublePointData;
    .locals 8

    .line 1
    sget-object v7, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    move-wide v0, p0

    move-wide v2, p2

    move-object v4, p4

    move-wide v5, p5

    invoke-static/range {v0 .. v7}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableDoublePointData;->create(JJLio/opentelemetry/api/common/Attributes;DLjava/util/List;)Lio/opentelemetry/sdk/metrics/data/DoublePointData;

    move-result-object p0

    return-object p0
.end method

.method public static create(JJLio/opentelemetry/api/common/Attributes;DLjava/util/List;)Lio/opentelemetry/sdk/metrics/data/DoublePointData;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "D",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/DoublePointData;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableDoublePointData;

    move-wide v1, p0

    move-wide v3, p2

    move-object v5, p4

    move-wide v6, p5

    move-object/from16 v8, p7

    invoke-direct/range {v0 .. v8}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableDoublePointData;-><init>(JJLio/opentelemetry/api/common/Attributes;DLjava/util/List;)V

    return-object v0
.end method
