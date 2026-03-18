.class public final Lqu/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqp/b;
.implements Lqp/e;
.implements Lqp/c;


# instance fields
.field public final d:Ltu/b;

.field public final e:Ltu/a;

.field public final f:Ltu/a;

.field public g:Lap0/o;

.field public h:Lsu/a;

.field public final i:Lqp/g;

.field public j:Lcom/google/android/gms/maps/model/CameraPosition;

.field public k:Lqu/b;

.field public final l:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

.field public m:Lnd0/c;

.field public n:Lnd0/c;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lqp/g;)V
    .locals 2

    .line 1
    new-instance v0, Ltu/b;

    .line 2
    .line 3
    invoke-direct {v0, p2}, Ltu/b;-><init>(Lqp/g;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v1, p0, Lqu/c;->l:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 15
    .line 16
    iput-object p2, p0, Lqu/c;->i:Lqp/g;

    .line 17
    .line 18
    iput-object v0, p0, Lqu/c;->d:Ltu/b;

    .line 19
    .line 20
    new-instance v1, Ltu/a;

    .line 21
    .line 22
    invoke-direct {v1, v0}, Ltu/a;-><init>(Ltu/b;)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lqu/c;->f:Ltu/a;

    .line 26
    .line 27
    new-instance v1, Ltu/a;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Ltu/a;-><init>(Ltu/b;)V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Lqu/c;->e:Ltu/a;

    .line 33
    .line 34
    new-instance v0, Lsu/i;

    .line 35
    .line 36
    invoke-direct {v0, p1, p2, p0}, Lsu/i;-><init>(Landroid/content/Context;Lqp/g;Lqu/c;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lqu/c;->h:Lsu/a;

    .line 40
    .line 41
    new-instance p1, Lru/g;

    .line 42
    .line 43
    new-instance p2, Lru/e;

    .line 44
    .line 45
    new-instance v0, Lru/c;

    .line 46
    .line 47
    invoke-direct {v0}, Lru/c;-><init>()V

    .line 48
    .line 49
    .line 50
    invoke-direct {p2, v0}, Lru/e;-><init>(Lru/c;)V

    .line 51
    .line 52
    .line 53
    const/4 v0, 0x6

    .line 54
    invoke-direct {p1, v0}, Lap0/o;-><init>(I)V

    .line 55
    .line 56
    .line 57
    iput-object p2, p1, Lru/g;->f:Lru/e;

    .line 58
    .line 59
    iput-object p1, p0, Lqu/c;->g:Lap0/o;

    .line 60
    .line 61
    new-instance p1, Lqu/b;

    .line 62
    .line 63
    invoke-direct {p1, p0}, Lqu/b;-><init>(Lqu/c;)V

    .line 64
    .line 65
    .line 66
    iput-object p1, p0, Lqu/c;->k:Lqu/b;

    .line 67
    .line 68
    iget-object p0, p0, Lqu/c;->h:Lsu/a;

    .line 69
    .line 70
    check-cast p0, Lsu/i;

    .line 71
    .line 72
    invoke-virtual {p0}, Lsu/i;->d()V

    .line 73
    .line 74
    .line 75
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    .line 1
    iget-object v0, p0, Lqu/c;->h:Lsu/a;

    .line 2
    .line 3
    instance-of v1, v0, Lqp/b;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    check-cast v0, Lqp/b;

    .line 8
    .line 9
    invoke-interface {v0}, Lqp/b;->a()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lqu/c;->g:Lap0/o;

    .line 13
    .line 14
    iget-object v1, p0, Lqu/c;->i:Lqp/g;

    .line 15
    .line 16
    invoke-virtual {v1}, Lqp/g;->b()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-interface {v0, v2}, Lru/f;->c(Lcom/google/android/gms/maps/model/CameraPosition;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lqu/c;->g:Lap0/o;

    .line 24
    .line 25
    invoke-interface {v0}, Lru/f;->k()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0}, Lqu/c;->c()V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_1
    iget-object v0, p0, Lqu/c;->j:Lcom/google/android/gms/maps/model/CameraPosition;

    .line 36
    .line 37
    if-eqz v0, :cond_3

    .line 38
    .line 39
    iget v0, v0, Lcom/google/android/gms/maps/model/CameraPosition;->e:F

    .line 40
    .line 41
    invoke-virtual {v1}, Lqp/g;->b()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    iget v2, v2, Lcom/google/android/gms/maps/model/CameraPosition;->e:F

    .line 46
    .line 47
    cmpl-float v0, v0, v2

    .line 48
    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    return-void

    .line 53
    :cond_3
    :goto_0
    invoke-virtual {v1}, Lqp/g;->b()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    iput-object v0, p0, Lqu/c;->j:Lcom/google/android/gms/maps/model/CameraPosition;

    .line 58
    .line 59
    invoke-virtual {p0}, Lqu/c;->c()V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public final b(Lsp/k;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lqu/c;->d:Ltu/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltu/b;->b(Lsp/k;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c()V
    .locals 3

    .line 1
    iget-object v0, p0, Lqu/c;->l:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 8
    .line 9
    .line 10
    :try_start_0
    iget-object v1, p0, Lqu/c;->k:Lqu/b;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-virtual {v1, v2}, Landroid/os/AsyncTask;->cancel(Z)Z

    .line 14
    .line 15
    .line 16
    new-instance v1, Lqu/b;

    .line 17
    .line 18
    invoke-direct {v1, p0}, Lqu/b;-><init>(Lqu/c;)V

    .line 19
    .line 20
    .line 21
    iput-object v1, p0, Lqu/c;->k:Lqu/b;

    .line 22
    .line 23
    sget-object v2, Landroid/os/AsyncTask;->THREAD_POOL_EXECUTOR:Ljava/util/concurrent/Executor;

    .line 24
    .line 25
    iget-object p0, p0, Lqu/c;->i:Lqp/g;

    .line 26
    .line 27
    invoke-virtual {p0}, Lqp/g;->b()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    iget p0, p0, Lcom/google/android/gms/maps/model/CameraPosition;->e:F

    .line 32
    .line 33
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    filled-new-array {p0}, [Ljava/lang/Float;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {v1, v2, p0}, Landroid/os/AsyncTask;->executeOnExecutor(Ljava/util/concurrent/Executor;[Ljava/lang/Object;)Landroid/os/AsyncTask;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 58
    .line 59
    .line 60
    throw p0
.end method

.method public final f(Lsp/k;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lqu/c;->d:Ltu/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltu/b;->f(Lsp/k;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
