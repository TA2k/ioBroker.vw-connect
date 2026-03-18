.class public abstract Lio/opentelemetry/sdk/internal/ComponentId;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/internal/ComponentId$Lazy;
    }
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/sdk/internal/ComponentId$1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/internal/ComponentId;-><init>()V

    return-void
.end method

.method public static generateLazy(Ljava/lang/String;)Lio/opentelemetry/sdk/internal/ComponentId;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/ComponentId$Lazy;

    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/internal/ComponentId$Lazy;-><init>(Ljava/lang/String;)V

    return-object v0
.end method

.method public static generateLazy(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Lio/opentelemetry/sdk/internal/StandardComponentId;
    .locals 1

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/internal/StandardComponentId;

    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/internal/StandardComponentId;-><init>(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)V

    return-object v0
.end method


# virtual methods
.method public abstract getComponentName()Ljava/lang/String;
.end method

.method public abstract getTypeName()Ljava/lang/String;
.end method
