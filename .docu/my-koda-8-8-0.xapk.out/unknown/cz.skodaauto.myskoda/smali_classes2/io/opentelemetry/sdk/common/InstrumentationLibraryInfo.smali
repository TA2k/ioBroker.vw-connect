.class public abstract Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Ljava/lang/Deprecated;
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final EMPTY:Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v0, v1}, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->create(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->EMPTY:Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 9
    .line 10
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

.method public static create(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .locals 2
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    const-string v0, "name"

    invoke-static {p0, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/common/AutoValue_InstrumentationLibraryInfo;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Lio/opentelemetry/sdk/common/AutoValue_InstrumentationLibraryInfo;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method public static create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
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
    new-instance v0, Lio/opentelemetry/sdk/common/AutoValue_InstrumentationLibraryInfo;

    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/common/AutoValue_InstrumentationLibraryInfo;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method public static empty()Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;->EMPTY:Lio/opentelemetry/sdk/common/InstrumentationLibraryInfo;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
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
