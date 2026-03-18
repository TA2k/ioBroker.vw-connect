.class public abstract Lnv/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;
.implements Landroidx/lifecycle/w;


# static fields
.field public static final h:Lb81/b;


# instance fields
.field public final d:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final e:Leb/j0;

.field public final f:Laq/a;

.field public final g:Ljava/util/concurrent/Executor;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lb81/b;

    .line 2
    .line 3
    const-string v1, "MobileVisionBase"

    .line 4
    .line 5
    const-string v2, ""

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lb81/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lnv/b;->h:Lb81/b;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Leb/j0;Ljava/util/concurrent/Executor;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lnv/b;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    iput-object p1, p0, Lnv/b;->e:Leb/j0;

    .line 13
    .line 14
    new-instance v0, Laq/a;

    .line 15
    .line 16
    invoke-direct {v0, v1}, Laq/a;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lnv/b;->f:Laq/a;

    .line 20
    .line 21
    iput-object p2, p0, Lnv/b;->g:Ljava/util/concurrent/Executor;

    .line 22
    .line 23
    iget-object p0, p1, Leb/j0;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 28
    .line 29
    .line 30
    iget-object p0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, La0/j;

    .line 33
    .line 34
    sget-object v0, Lnv/e;->a:Lnv/e;

    .line 35
    .line 36
    invoke-virtual {p1, p2, v0, p0}, Leb/j0;->q(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;La0/j;)Laq/t;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lnv/d;->d:Lnv/d;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Laq/t;->l(Laq/f;)Laq/t;

    .line 43
    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final declared-synchronized b(Lmv/a;)Laq/t;
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lnv/b;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 3
    .line 4
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance p1, Lbv/a;

    .line 11
    .line 12
    const-string v0, "This detector is already closed!"

    .line 13
    .line 14
    const/16 v1, 0xe

    .line 15
    .line 16
    invoke-direct {p1, v0, v1}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 20
    .line 21
    .line 22
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    monitor-exit p0

    .line 24
    return-object p1

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    :try_start_1
    iget v0, p1, Lmv/a;->c:I

    .line 28
    .line 29
    const/16 v1, 0x20

    .line 30
    .line 31
    if-lt v0, v1, :cond_1

    .line 32
    .line 33
    iget v0, p1, Lmv/a;->d:I

    .line 34
    .line 35
    if-lt v0, v1, :cond_1

    .line 36
    .line 37
    iget-object v0, p0, Lnv/b;->e:Leb/j0;

    .line 38
    .line 39
    iget-object v1, p0, Lnv/b;->g:Ljava/util/concurrent/Executor;

    .line 40
    .line 41
    new-instance v2, Lcq/s1;

    .line 42
    .line 43
    const/4 v3, 0x1

    .line 44
    invoke-direct {v2, v3, p0, p1}, Lcq/s1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-object p1, p0, Lnv/b;->f:Laq/a;

    .line 48
    .line 49
    iget-object p1, p1, Laq/a;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p1, La0/j;

    .line 52
    .line 53
    invoke-virtual {v0, v1, v2, p1}, Leb/j0;->q(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;La0/j;)Laq/t;

    .line 54
    .line 55
    .line 56
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    monitor-exit p0

    .line 58
    return-object p1

    .line 59
    :cond_1
    :try_start_2
    new-instance p1, Lbv/a;

    .line 60
    .line 61
    const-string v0, "InputImage width and height should be at least 32!"

    .line 62
    .line 63
    const/4 v1, 0x3

    .line 64
    invoke-direct {p1, v0, v1}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {p1}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 68
    .line 69
    .line 70
    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 71
    monitor-exit p0

    .line 72
    return-object p1

    .line 73
    :goto_0
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 74
    throw p1
.end method

.method public declared-synchronized close()V
    .locals 5
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lnv/b;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Lnv/b;->f:Laq/a;

    .line 12
    .line 13
    invoke-virtual {v0}, Laq/a;->k()V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lnv/b;->e:Leb/j0;

    .line 17
    .line 18
    iget-object v2, p0, Lnv/b;->g:Ljava/util/concurrent/Executor;

    .line 19
    .line 20
    iget-object v3, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v3, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-lez v3, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v1, 0x0

    .line 32
    :goto_0
    invoke-static {v1}, Lno/c0;->k(Z)V

    .line 33
    .line 34
    .line 35
    new-instance v1, Laq/k;

    .line 36
    .line 37
    invoke-direct {v1}, Laq/k;-><init>()V

    .line 38
    .line 39
    .line 40
    new-instance v3, Llr/b;

    .line 41
    .line 42
    const/4 v4, 0x6

    .line 43
    invoke-direct {v3, v4, v0, v1}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v0, La8/b;

    .line 49
    .line 50
    invoke-virtual {v0, v2, v3}, La8/b;->s(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    .line 53
    monitor-exit p0

    .line 54
    return-void

    .line 55
    :catchall_0
    move-exception v0

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    monitor-exit p0

    .line 58
    return-void

    .line 59
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 60
    throw v0
.end method
