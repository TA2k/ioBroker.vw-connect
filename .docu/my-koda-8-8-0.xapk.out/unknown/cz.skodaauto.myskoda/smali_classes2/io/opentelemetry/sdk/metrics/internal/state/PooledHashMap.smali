.class public final Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Map;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/Map<",
        "TK;TV;>;"
    }
.end annotation


# static fields
.field private static final DEFAULT_CAPACITY:I = 0x10

.field private static final LOAD_FACTOR:F = 0.75f


# instance fields
.field private final entryPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool<",
            "Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry<",
            "TK;TV;>;>;"
        }
    .end annotation
.end field

.field private size:I

.field private table:[Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Ljava/util/ArrayList<",
            "Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry<",
            "TK;TV;>;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    const/16 v0, 0x10

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-array p1, p1, [Ljava/util/ArrayList;

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 3
    new-instance p1, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    new-instance v0, Lio/opentelemetry/exporter/internal/grpc/b;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/grpc/b;-><init>(I)V

    invoke-direct {p1, v0}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;-><init>(Ljava/util/function/Supplier;)V

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->entryPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    const/4 p1, 0x0

    .line 4
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    return-void
.end method

.method public static synthetic a()Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->lambda$new$0()Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private getBucket(Ljava/lang/Object;)I
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)I"
        }
    .end annotation

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 6
    .line 7
    array-length p0, p0

    .line 8
    rem-int/2addr p1, p0

    .line 9
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method private static synthetic lambda$new$0()Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;-><init>(Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method private rehash()V
    .locals 7

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    mul-int/lit8 v1, v1, 0x2

    .line 5
    .line 6
    new-array v1, v1, [Ljava/util/ArrayList;

    .line 7
    .line 8
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 12
    .line 13
    :goto_0
    array-length v2, v0

    .line 14
    if-ge v1, v2, :cond_2

    .line 15
    .line 16
    aget-object v2, v0, v1

    .line 17
    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-eqz v4, :cond_0

    .line 29
    .line 30
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    check-cast v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 35
    .line 36
    iget-object v5, v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->key:Ljava/lang/Object;

    .line 37
    .line 38
    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    iget-object v6, v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 42
    .line 43
    invoke-static {v6}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v5, v6}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    iget-object v5, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->entryPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 50
    .line 51
    invoke-virtual {v5, v4}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->returnObject(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 56
    .line 57
    .line 58
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    return-void
.end method


# virtual methods
.method public clear()V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 4
    .line 5
    array-length v3, v2

    .line 6
    if-ge v1, v3, :cond_2

    .line 7
    .line 8
    aget-object v2, v2, v1

    .line 9
    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    move v3, v0

    .line 13
    :goto_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-ge v3, v4, :cond_0

    .line 18
    .line 19
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    check-cast v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 24
    .line 25
    iget-object v5, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->entryPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 26
    .line 27
    invoke-virtual {v5, v4}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->returnObject(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    add-int/lit8 v3, v3, 0x1

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 34
    .line 35
    .line 36
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 40
    .line 41
    return-void
.end method

.method public containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    const-string v0, "This map does not support null keys"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public containsValue(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public entrySet()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/util/Map$Entry<",
            "TK;TV;>;>;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public forEach(Ljava/util/function/BiConsumer;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiConsumer<",
            "-TK;-TV;>;)V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 4
    .line 5
    array-length v3, v2

    .line 6
    if-ge v1, v3, :cond_1

    .line 7
    .line 8
    aget-object v2, v2, v1

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    move v3, v0

    .line 13
    :goto_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-ge v3, v4, :cond_0

    .line 18
    .line 19
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    check-cast v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 24
    .line 25
    iget-object v5, v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->key:Ljava/lang/Object;

    .line 26
    .line 27
    iget-object v4, v4, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 28
    .line 29
    invoke-interface {p1, v5, v4}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    add-int/lit8 v3, v3, 0x1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    return-void
.end method

.method public get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            ")TV;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const-string v0, "This map does not support null keys"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->getBucket(Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 11
    .line 12
    aget-object p0, p0, v0

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    :goto_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-ge v0, v1, :cond_1

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 28
    .line 29
    iget-object v2, v1, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->key:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {v2, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    iget-object p0, v1, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    const/4 p0, 0x0

    .line 44
    return-object p0
.end method

.method public isEmpty()Z
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public keySet()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "TK;>;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;TV;)TV;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const-string v0, "This map does not support null keys"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    const-string v0, "This map does not support null values"

    .line 7
    .line 8
    invoke-static {p2, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 12
    .line 13
    int-to-float v0, v0

    .line 14
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 15
    .line 16
    array-length v1, v1

    .line 17
    int-to-float v1, v1

    .line 18
    const/high16 v2, 0x3f400000    # 0.75f

    .line 19
    .line 20
    mul-float/2addr v1, v2

    .line 21
    cmpl-float v0, v0, v1

    .line 22
    .line 23
    if-lez v0, :cond_0

    .line 24
    .line 25
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->rehash()V

    .line 26
    .line 27
    .line 28
    :cond_0
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->getBucket(Ljava/lang/Object;)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 33
    .line 34
    aget-object v1, v1, v0

    .line 35
    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    new-instance v1, Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 41
    .line 42
    .line 43
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 44
    .line 45
    aput-object v1, v2, v0

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/4 v0, 0x0

    .line 49
    :goto_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-ge v0, v2, :cond_3

    .line 54
    .line 55
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    check-cast v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 60
    .line 61
    iget-object v3, v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->key:Ljava/lang/Object;

    .line 62
    .line 63
    invoke-static {v3, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eqz v3, :cond_2

    .line 68
    .line 69
    iget-object p0, v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 70
    .line 71
    iput-object p2, v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 72
    .line 73
    return-object p0

    .line 74
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    :goto_1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->entryPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 78
    .line 79
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->borrowObject()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 84
    .line 85
    iput-object p1, v0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->key:Ljava/lang/Object;

    .line 86
    .line 87
    iput-object p2, v0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 88
    .line 89
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    iget p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 93
    .line 94
    add-int/lit8 p1, p1, 0x1

    .line 95
    .line 96
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 97
    .line 98
    const/4 p0, 0x0

    .line 99
    return-object p0
.end method

.method public putAll(Ljava/util/Map;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "+TK;+TV;>;)V"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            ")TV;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const-string v0, "This map does not support null keys"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->getBucket(Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->table:[Ljava/util/ArrayList;

    .line 11
    .line 12
    aget-object v0, v1, v0

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    :goto_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-ge v1, v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;

    .line 28
    .line 29
    iget-object v3, v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->key:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {v3, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    iget-object p1, v2, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap$Entry;->value:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->entryPool:Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;

    .line 43
    .line 44
    invoke-virtual {v0, v2}, Lio/opentelemetry/sdk/metrics/internal/state/ObjectPool;->returnObject(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 48
    .line 49
    add-int/lit8 v0, v0, -0x1

    .line 50
    .line 51
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 52
    .line 53
    return-object p1

    .line 54
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    const/4 p0, 0x0

    .line 58
    return-object p0
.end method

.method public size()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/PooledHashMap;->size:I

    .line 2
    .line 3
    return p0
.end method

.method public values()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "TV;>;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
