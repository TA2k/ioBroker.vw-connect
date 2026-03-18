.class public abstract Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "AdviceBuilder"
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


# virtual methods
.method public abstract attributes(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
    .param p1    # Ljava/util/List;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;)",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;"
        }
    .end annotation
.end method

.method public abstract build()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;
.end method

.method public abstract explicitBucketBoundaries(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
    .param p1    # Ljava/util/List;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;"
        }
    .end annotation
.end method

.method public setAttributes(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
    .locals 1
    .param p1    # Ljava/util/List;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;)",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;->attributes(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public setExplicitBucketBoundaries(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
    .locals 1
    .param p1    # Ljava/util/List;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;->explicitBucketBoundaries(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
