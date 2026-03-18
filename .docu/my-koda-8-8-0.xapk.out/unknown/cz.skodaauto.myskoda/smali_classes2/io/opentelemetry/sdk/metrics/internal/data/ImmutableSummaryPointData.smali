.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/SummaryPointData;


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

.method public static create(JJLio/opentelemetry/api/common/Attributes;JDLjava/util/List;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryPointData;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "JD",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryPointData;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSummaryPointData;

    .line 2
    .line 3
    sget-object v6, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 4
    .line 5
    move-wide v1, p0

    .line 6
    move-wide v3, p2

    .line 7
    move-object/from16 v5, p4

    .line 8
    .line 9
    move-wide/from16 v7, p5

    .line 10
    .line 11
    move-wide/from16 v9, p7

    .line 12
    .line 13
    move-object/from16 v11, p9

    .line 14
    .line 15
    invoke-direct/range {v0 .. v11}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSummaryPointData;-><init>(JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;JDLjava/util/List;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
