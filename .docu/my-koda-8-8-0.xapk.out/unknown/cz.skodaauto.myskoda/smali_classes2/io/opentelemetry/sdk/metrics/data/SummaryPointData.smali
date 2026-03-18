.class public interface abstract Lio/opentelemetry/sdk/metrics/data/SummaryPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/PointData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(JJLio/opentelemetry/api/common/Attributes;JDLjava/util/List;)Lio/opentelemetry/sdk/metrics/data/SummaryPointData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "JD",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/SummaryPointData;"
        }
    .end annotation

    .line 1
    invoke-static/range {p0 .. p9}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryPointData;->create(JJLio/opentelemetry/api/common/Attributes;JDLjava/util/List;)Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSummaryPointData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getCount()J
.end method

.method public abstract getSum()D
.end method

.method public abstract getValues()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/ValueAtQuantile;",
            ">;"
        }
    .end annotation
.end method
