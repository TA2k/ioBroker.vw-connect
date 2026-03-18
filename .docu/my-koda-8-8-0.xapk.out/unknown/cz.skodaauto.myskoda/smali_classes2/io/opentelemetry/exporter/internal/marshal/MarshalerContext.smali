.class public final Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;,
        Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;,
        Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;
    }
.end annotation


# static fields
.field private static final KEY_INDEX:Ljava/util/concurrent/atomic/AtomicInteger;


# instance fields
.field private data:[Ljava/lang/Object;

.field private dataReadIndex:I

.field private dataWriteIndex:I

.field private instances:[Ljava/lang/Object;

.field private final listPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool<",
            "Ljava/util/List<",
            "*>;>;"
        }
    .end annotation
.end field

.field private final mapPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool<",
            "Ljava/util/Map<",
            "**>;>;"
        }
    .end annotation
.end field

.field private final marshalStringNoAllocation:Z

.field private final marshalStringUnsafe:Z

.field private sizeReadIndex:I

.field private sizeWriteIndex:I

.field private sizes:[I

.field private final spanIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

.field private final traceIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->KEY_INDEX:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x1

    .line 1
    invoke-direct {p0, v0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;-><init>(ZZ)V

    return-void
.end method

.method public constructor <init>(ZZ)V
    .locals 5

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0x10

    .line 3
    new-array v1, v0, [I

    iput-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizes:[I

    .line 4
    new-array v1, v0, [Ljava/lang/Object;

    iput-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->data:[Ljava/lang/Object;

    .line 5
    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getLength()I

    move-result v2

    div-int/lit8 v2, v2, 0x2

    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;-><init>(I)V

    iput-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->traceIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    .line 6
    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getLength()I

    move-result v2

    div-int/lit8 v2, v2, 0x2

    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;-><init>(I)V

    iput-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->spanIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    .line 7
    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    new-instance v2, Lio/opentelemetry/exporter/internal/marshal/a;

    const/4 v3, 0x0

    invoke-direct {v2, v3}, Lio/opentelemetry/exporter/internal/marshal/a;-><init>(I)V

    new-instance v3, Lio/opentelemetry/exporter/internal/marshal/b;

    const/4 v4, 0x0

    invoke-direct {v3, v4}, Lio/opentelemetry/exporter/internal/marshal/b;-><init>(I)V

    invoke-direct {v1, v2, v3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;-><init>(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    iput-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->mapPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    .line 8
    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    new-instance v2, Lio/opentelemetry/exporter/internal/marshal/a;

    const/4 v3, 0x1

    invoke-direct {v2, v3}, Lio/opentelemetry/exporter/internal/marshal/a;-><init>(I)V

    new-instance v3, Lio/opentelemetry/exporter/internal/marshal/b;

    const/4 v4, 0x1

    invoke-direct {v3, v4}, Lio/opentelemetry/exporter/internal/marshal/b;-><init>(I)V

    invoke-direct {v1, v2, v3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;-><init>(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    iput-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->listPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    .line 9
    new-array v0, v0, [Ljava/lang/Object;

    iput-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->instances:[Ljava/lang/Object;

    .line 10
    iput-boolean p1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringNoAllocation:Z

    .line 11
    iput-boolean p2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringUnsafe:Z

    return-void
.end method

.method public static synthetic access$000()Ljava/util/concurrent/atomic/AtomicInteger;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->KEY_INDEX:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    return-object v0
.end method

.method private growDataIfNeeded()V
    .locals 4

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataWriteIndex:I

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->data:[Ljava/lang/Object;

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    if-ne v0, v2, :cond_0

    .line 7
    .line 8
    array-length v0, v1

    .line 9
    mul-int/lit8 v0, v0, 0x2

    .line 10
    .line 11
    new-array v0, v0, [Ljava/lang/Object;

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-static {v1, v3, v0, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->data:[Ljava/lang/Object;

    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method private growSizeIfNeeded()V
    .locals 4

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeWriteIndex:I

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizes:[I

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    if-ne v0, v2, :cond_0

    .line 7
    .line 8
    array-length v0, v1

    .line 9
    mul-int/lit8 v0, v0, 0x2

    .line 10
    .line 11
    new-array v0, v0, [I

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-static {v1, v3, v0, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizes:[I

    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public static key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public addData(Ljava/lang/Object;)V
    .locals 3
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->growDataIfNeeded()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->data:[Ljava/lang/Object;

    .line 5
    .line 6
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataWriteIndex:I

    .line 7
    .line 8
    add-int/lit8 v2, v1, 0x1

    .line 9
    .line 10
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataWriteIndex:I

    .line 11
    .line 12
    aput-object p1, v0, v1

    .line 13
    .line 14
    return-void
.end method

.method public addSize()I
    .locals 2

    .line 3
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->growSizeIfNeeded()V

    .line 4
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeWriteIndex:I

    add-int/lit8 v1, v0, 0x1

    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeWriteIndex:I

    return v0
.end method

.method public addSize(I)V
    .locals 3

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->growSizeIfNeeded()V

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizes:[I

    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeWriteIndex:I

    add-int/lit8 v2, v1, 0x1

    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeWriteIndex:I

    aput p1, v0, v1

    return-void
.end method

.method public getData(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Class<",
            "TT;>;)TT;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->data:[Ljava/lang/Object;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataReadIndex:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataReadIndex:I

    .line 8
    .line 9
    aget-object p0, v0, v1

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public getIdentityMap()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            ">()",
            "Ljava/util/Map<",
            "TK;TV;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->mapPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/Map;

    .line 8
    .line 9
    return-object p0
.end method

.method public getInstance(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;Ljava/util/function/Supplier;)Ljava/lang/Object;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;",
            "Ljava/util/function/Supplier<",
            "TT;>;)TT;"
        }
    .end annotation

    .line 1
    iget v0, p1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;->index:I

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->instances:[Ljava/lang/Object;

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    if-lt v0, v2, :cond_0

    .line 7
    .line 8
    array-length v0, v1

    .line 9
    mul-int/lit8 v0, v0, 0x2

    .line 10
    .line 11
    new-array v0, v0, [Ljava/lang/Object;

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-static {v1, v3, v0, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->instances:[Ljava/lang/Object;

    .line 19
    .line 20
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->instances:[Ljava/lang/Object;

    .line 21
    .line 22
    iget v1, p1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;->index:I

    .line 23
    .line 24
    aget-object v0, v0, v1

    .line 25
    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    invoke-interface {p2}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->instances:[Ljava/lang/Object;

    .line 33
    .line 34
    iget p1, p1, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;->index:I

    .line 35
    .line 36
    aput-object p2, p0, p1

    .line 37
    .line 38
    return-object p2

    .line 39
    :cond_1
    return-object v0
.end method

.method public getList()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">()",
            "Ljava/util/List<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->listPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/List;

    .line 8
    .line 9
    return-object p0
.end method

.method public getSize()I
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizes:[I

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeReadIndex:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeReadIndex:I

    .line 8
    .line 9
    aget p0, v0, v1

    .line 10
    .line 11
    return p0
.end method

.method public getSpanIdBuffer()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->spanIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->get()[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getTraceIdBuffer()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->traceIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->get()[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public marshalStringNoAllocation()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringNoAllocation:Z

    .line 2
    .line 3
    return p0
.end method

.method public marshalStringUnsafe()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringUnsafe:Z

    .line 2
    .line 3
    return p0
.end method

.method public reset()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeReadIndex:I

    .line 3
    .line 4
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeWriteIndex:I

    .line 5
    .line 6
    move v1, v0

    .line 7
    :goto_0
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataWriteIndex:I

    .line 8
    .line 9
    if-ge v1, v2, :cond_0

    .line 10
    .line 11
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->data:[Ljava/lang/Object;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    aput-object v3, v2, v1

    .line 15
    .line 16
    add-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataReadIndex:I

    .line 20
    .line 21
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataWriteIndex:I

    .line 22
    .line 23
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->traceIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    .line 24
    .line 25
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->reset()V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->spanIdPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;

    .line 29
    .line 30
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$IdPool;->reset()V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->mapPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    .line 34
    .line 35
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;->reset()V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->listPool:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;

    .line 39
    .line 40
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Pool;->reset()V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public resetReadIndex()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizeReadIndex:I

    .line 3
    .line 4
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->dataReadIndex:I

    .line 5
    .line 6
    return-void
.end method

.method public setSize(II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->sizes:[I

    .line 2
    .line 3
    aput p2, p0, p1

    .line 4
    .line 5
    return-void
.end method
