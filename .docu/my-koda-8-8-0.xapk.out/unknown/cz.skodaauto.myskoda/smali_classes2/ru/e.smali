.class public final Lru/e;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lru/c;

.field public final g:Landroidx/collection/w;

.field public final h:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

.field public final i:Ljava/util/concurrent/ExecutorService;


# direct methods
.method public constructor <init>(Lru/c;)V
    .locals 2

    .line 1
    const/4 v0, 0x6

    .line 2
    invoke-direct {p0, v0}, Lap0/o;-><init>(I)V

    .line 3
    .line 4
    .line 5
    new-instance v0, Landroidx/collection/w;

    .line 6
    .line 7
    const/4 v1, 0x5

    .line 8
    invoke-direct {v0, v1}, Landroidx/collection/w;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lru/e;->g:Landroidx/collection/w;

    .line 12
    .line 13
    new-instance v0, Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lru/e;->h:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 19
    .line 20
    invoke-static {}, Ljava/util/concurrent/Executors;->newCachedThreadPool()Ljava/util/concurrent/ExecutorService;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Lru/e;->i:Ljava/util/concurrent/ExecutorService;

    .line 25
    .line 26
    iput-object p1, p0, Lru/e;->f:Lru/c;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final b()Ljava/util/Collection;
    .locals 0

    .line 1
    iget-object p0, p0, Lru/e;->f:Lru/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Lru/c;->b()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b0(I)Ljava/util/Set;
    .locals 4

    .line 1
    iget-object v0, p0, Lru/e;->h:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/Lock;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 8
    .line 9
    .line 10
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object v2, p0, Lru/e;->g:Landroidx/collection/w;

    .line 15
    .line 16
    invoke-virtual {v2, v1}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Ljava/util/Set;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/Lock;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-interface {v3}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 27
    .line 28
    .line 29
    if-nez v1, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 36
    .line 37
    .line 38
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v2, v1}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    check-cast v1, Ljava/util/Set;

    .line 47
    .line 48
    if-nez v1, :cond_0

    .line 49
    .line 50
    iget-object p0, p0, Lru/e;->f:Lru/c;

    .line 51
    .line 52
    int-to-float v1, p1

    .line 53
    invoke-virtual {p0, v1}, Lru/c;->m(F)Ljava/util/Set;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {v2, p0, v1}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    :cond_0
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 69
    .line 70
    .line 71
    :cond_1
    return-object v1
.end method

.method public final e(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lru/e;->f:Lru/c;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lru/c;->e(Ljava/util/Collection;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lru/e;->g:Landroidx/collection/w;

    .line 10
    .line 11
    invoke-virtual {p0}, Landroidx/collection/w;->evictAll()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return p1
.end method

.method public final g()V
    .locals 1

    .line 1
    iget-object v0, p0, Lru/e;->f:Lru/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lru/c;->g()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lru/e;->g:Landroidx/collection/w;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/collection/w;->evictAll()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final m(F)Ljava/util/Set;
    .locals 6

    .line 1
    float-to-int p1, p1

    .line 2
    invoke-virtual {p0, p1}, Lru/e;->b0(I)Ljava/util/Set;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    add-int/lit8 v1, p1, 0x1

    .line 7
    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    iget-object v3, p0, Lru/e;->g:Landroidx/collection/w;

    .line 13
    .line 14
    invoke-virtual {v3, v2}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    iget-object v4, p0, Lru/e;->i:Ljava/util/concurrent/ExecutorService;

    .line 19
    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    new-instance v2, Lcom/google/android/material/datepicker/n;

    .line 23
    .line 24
    const/4 v5, 0x2

    .line 25
    invoke-direct {v2, p0, v1, v5}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v4, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    add-int/lit8 p1, p1, -0x1

    .line 32
    .line 33
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {v3, v1}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    if-nez v1, :cond_1

    .line 42
    .line 43
    new-instance v1, Lcom/google/android/material/datepicker/n;

    .line 44
    .line 45
    const/4 v2, 0x2

    .line 46
    invoke-direct {v1, p0, p1, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 47
    .line 48
    .line 49
    invoke-interface {v4, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 50
    .line 51
    .line 52
    :cond_1
    return-object v0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lru/e;->f:Lru/c;

    .line 2
    .line 3
    iget p0, p0, Lru/c;->f:I

    .line 4
    .line 5
    return p0
.end method
