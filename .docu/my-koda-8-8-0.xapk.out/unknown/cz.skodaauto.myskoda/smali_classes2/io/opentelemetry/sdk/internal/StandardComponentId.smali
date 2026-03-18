.class public Lio/opentelemetry/sdk/internal/StandardComponentId;
.super Lio/opentelemetry/sdk/internal/ComponentId$Lazy;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
    }
.end annotation


# instance fields
.field private final standardType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)V
    .locals 1

    .line 1
    iget-object v0, p1, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->value:Ljava/lang/String;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/internal/ComponentId$Lazy;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/StandardComponentId;->standardType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public bridge synthetic getComponentName()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/sdk/internal/ComponentId$Lazy;->getComponentName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getStandardType()Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/StandardComponentId;->standardType:Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getTypeName()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/sdk/internal/ComponentId$Lazy;->getTypeName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
