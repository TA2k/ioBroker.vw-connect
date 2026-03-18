.class public final Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final root:Lio/opentelemetry/sdk/trace/samplers/Sampler;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/trace/samplers/Sampler;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 6
    .line 7
    iget-object v3, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 8
    .line 9
    iget-object v4, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 10
    .line 11
    iget-object v5, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 12
    .line 13
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;-><init>(Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public setLocalParentNotSampled(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    return-object p0
.end method

.method public setLocalParentSampled(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    return-object p0
.end method

.method public setRemoteParentNotSampled(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    return-object p0
.end method

.method public setRemoteParentSampled(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    return-object p0
.end method
