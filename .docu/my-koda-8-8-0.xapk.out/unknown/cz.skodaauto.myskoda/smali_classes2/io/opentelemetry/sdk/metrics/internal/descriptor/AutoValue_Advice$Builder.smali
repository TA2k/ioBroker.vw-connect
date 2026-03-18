.class final Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice$Builder;
.super Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation


# instance fields
.field private attributes:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;>;"
        }
    .end annotation
.end field

.field private explicitBucketBoundaries:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public attributes(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
    .locals 0
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
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice$Builder;->attributes:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice$Builder;->explicitBucketBoundaries:Ljava/util/List;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice$Builder;->attributes:Ljava/util/List;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v0, v1, p0, v2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice;-><init>(Ljava/util/List;Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice$1;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public explicitBucketBoundaries(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/internal/descriptor/Advice$AdviceBuilder;
    .locals 0
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
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/descriptor/AutoValue_Advice$Builder;->explicitBucketBoundaries:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method
