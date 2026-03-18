.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/HistogramPointData;


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

.method public static create(JJLio/opentelemetry/api/common/Attributes;DZDZDLjava/util/List;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;
    .locals 17
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "DZDZD",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;"
        }
    .end annotation

    .line 1
    sget-object v16, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    move-wide/from16 v1, p0

    move-wide/from16 v3, p2

    move-object/from16 v5, p4

    move-wide/from16 v6, p5

    move/from16 v8, p7

    move-wide/from16 v9, p8

    move/from16 v11, p10

    move-wide/from16 v12, p11

    move-object/from16 v14, p13

    move-object/from16 v15, p14

    .line 2
    invoke-static/range {v1 .. v16}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;->create(JJLio/opentelemetry/api/common/Attributes;DZDZDLjava/util/List;Ljava/util/List;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;

    move-result-object v0

    return-object v0
.end method

.method public static create(JJLio/opentelemetry/api/common/Attributes;DZDZDLjava/util/List;Ljava/util/List;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;
    .locals 24
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "DZDZD",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/data/ImmutableHistogramPointData;"
        }
    .end annotation

    .line 3
    invoke-interface/range {p14 .. p14}, Ljava/util/List;->size()I

    move-result v0

    invoke-interface/range {p13 .. p13}, Ljava/util/List;->size()I

    move-result v1

    add-int/lit8 v1, v1, 0x1

    if-ne v0, v1, :cond_1

    .line 4
    invoke-static/range {p13 .. p13}, Lio/opentelemetry/sdk/metrics/internal/data/HistogramPointDataValidations;->validateIsStrictlyIncreasing(Ljava/util/List;)V

    .line 5
    invoke-static/range {p13 .. p13}, Lio/opentelemetry/sdk/metrics/internal/data/HistogramPointDataValidations;->validateFiniteBoundaries(Ljava/util/List;)V

    .line 6
    invoke-static/range {p14 .. p14}, Lio/opentelemetry/sdk/internal/PrimitiveLongList;->toArray(Ljava/util/List;)[J

    move-result-object v0

    array-length v1, v0

    const-wide/16 v2, 0x0

    const/4 v4, 0x0

    move-wide v13, v2

    :goto_0
    if-ge v4, v1, :cond_0

    aget-wide v2, v0, v4

    add-long/2addr v13, v2

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    .line 7
    :cond_0
    new-instance v5, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableHistogramPointData;

    new-instance v0, Ljava/util/ArrayList;

    move-object/from16 v1, p13

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 8
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v21

    new-instance v0, Ljava/util/ArrayList;

    move-object/from16 v2, p14

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 9
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v22

    move-wide/from16 v6, p0

    move-wide/from16 v8, p2

    move-object/from16 v10, p4

    move-wide/from16 v11, p5

    move/from16 v15, p7

    move-wide/from16 v16, p8

    move/from16 v18, p10

    move-wide/from16 v19, p11

    move-object/from16 v23, p15

    invoke-direct/range {v5 .. v23}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableHistogramPointData;-><init>(JJLio/opentelemetry/api/common/Attributes;DJZDZDLjava/util/List;Ljava/util/List;Ljava/util/List;)V

    return-object v5

    :cond_1
    move-object/from16 v1, p13

    move-object/from16 v2, p14

    .line 10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "invalid counts: size should be "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    add-int/lit8 v1, v1, 0x1

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " instead of "

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v1

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
