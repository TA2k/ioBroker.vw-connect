.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;


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

.method public static create(IDJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;
    .locals 26
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IDJZDZD",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            "JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;"
        }
    .end annotation

    .line 1
    invoke-interface/range {p11 .. p11}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getTotalCount()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    add-long v0, v0, p3

    .line 6
    .line 7
    invoke-interface/range {p12 .. p12}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getTotalCount()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    add-long v13, v2, v0

    .line 12
    .line 13
    new-instance v4, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramPointData;

    .line 14
    .line 15
    move/from16 v10, p0

    .line 16
    .line 17
    move-wide/from16 v11, p1

    .line 18
    .line 19
    move-wide/from16 v15, p3

    .line 20
    .line 21
    move/from16 v17, p5

    .line 22
    .line 23
    move-wide/from16 v18, p6

    .line 24
    .line 25
    move/from16 v20, p8

    .line 26
    .line 27
    move-wide/from16 v21, p9

    .line 28
    .line 29
    move-object/from16 v23, p11

    .line 30
    .line 31
    move-object/from16 v24, p12

    .line 32
    .line 33
    move-wide/from16 v5, p13

    .line 34
    .line 35
    move-wide/from16 v7, p15

    .line 36
    .line 37
    move-object/from16 v9, p17

    .line 38
    .line 39
    move-object/from16 v25, p18

    .line 40
    .line 41
    invoke-direct/range {v4 .. v25}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramPointData;-><init>(JJLio/opentelemetry/api/common/Attributes;IDJJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Ljava/util/List;)V

    .line 42
    .line 43
    .line 44
    return-object v4
.end method
