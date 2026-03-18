.class Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "IdPool"
.end annotation


# instance fields
.field final idSize:I

.field index:I

.field private final pool:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "[B>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->pool:Ljava/util/List;

    .line 10
    .line 11
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->idSize:I

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public get()[B
    .locals 3

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->index:I

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->pool:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-ge v0, v1, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->pool:Ljava/util/List;

    .line 12
    .line 13
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->index:I

    .line 14
    .line 15
    add-int/lit8 v2, v1, 0x1

    .line 16
    .line 17
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->index:I

    .line 18
    .line 19
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, [B

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_0
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->idSize:I

    .line 27
    .line 28
    new-array v0, v0, [B

    .line 29
    .line 30
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->pool:Ljava/util/List;

    .line 31
    .line 32
    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->index:I

    .line 36
    .line 37
    add-int/lit8 v1, v1, 0x1

    .line 38
    .line 39
    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->index:I

    .line 40
    .line 41
    return-object v0
.end method

.method public reset()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->index:I

    .line 3
    .line 4
    return-void
.end method
