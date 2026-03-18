.class public abstract Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final EMPTY:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->create(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->EMPTY:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 2

    const/4 v0, 0x0

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v1

    invoke-static {p0, v0, v0, v1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    move-result-object p0

    return-object p0
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 2
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    move-result-object p0

    return-object p0
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 3
    const-string v0, "name"

    invoke-static {p0, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    const-string v0, "attributes"

    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    new-instance v0, Lio/opentelemetry/sdk/common/AutoValue_InstrumentationScopeInfo;

    invoke-direct {v0, p0, p1, p2, p3}, Lio/opentelemetry/sdk/common/AutoValue_InstrumentationScopeInfo;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    return-object v0
.end method

.method public static empty()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->EMPTY:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract getAttributes()Lio/opentelemetry/api/common/Attributes;
.end method

.method public abstract getName()Ljava/lang/String;
.end method

.method public abstract getSchemaUrl()Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getVersion()Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method
