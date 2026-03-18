.class public final Ldu/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/util/HashMap;

.field public static final e:Lha/c;


# instance fields
.field public final a:Ljava/util/concurrent/Executor;

.field public final b:Ldu/o;

.field public c:Laq/t;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ldu/c;->d:Ljava/util/HashMap;

    .line 7
    .line 8
    new-instance v0, Lha/c;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lha/c;-><init>(I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Ldu/c;->e:Lha/c;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Ldu/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldu/c;->a:Ljava/util/concurrent/Executor;

    .line 5
    .line 6
    iput-object p2, p0, Ldu/c;->b:Ldu/o;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Ldu/c;->c:Laq/t;

    .line 10
    .line 11
    return-void
.end method

.method public static a(Laq/j;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    new-instance v1, La0/j;

    .line 4
    .line 5
    const/16 v2, 0x10

    .line 6
    .line 7
    invoke-direct {v1, v2}, La0/j;-><init>(I)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Ldu/c;->e:Lha/c;

    .line 11
    .line 12
    invoke-virtual {p0, v2, v1}, Laq/j;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v2, v1}, Laq/j;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v2, v1}, Laq/j;->a(Ljava/util/concurrent/Executor;Laq/d;)Laq/t;

    .line 19
    .line 20
    .line 21
    iget-object v1, v1, La0/j;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Ljava/util/concurrent/CountDownLatch;

    .line 24
    .line 25
    const-wide/16 v2, 0x5

    .line 26
    .line 27
    invoke-virtual {v1, v2, v3, v0}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0}, Laq/j;->i()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    invoke-virtual {p0}, Laq/j;->g()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_0
    new-instance v0, Ljava/util/concurrent/ExecutionException;

    .line 45
    .line 46
    invoke-virtual {p0}, Laq/j;->f()Ljava/lang/Exception;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-direct {v0, p0}, Ljava/util/concurrent/ExecutionException;-><init>(Ljava/lang/Throwable;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_1
    new-instance p0, Ljava/util/concurrent/TimeoutException;

    .line 55
    .line 56
    const-string v0, "Task await timed out."

    .line 57
    .line 58
    invoke-direct {p0, v0}, Ljava/util/concurrent/TimeoutException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0
.end method


# virtual methods
.method public final declared-synchronized b()Laq/j;
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ldu/c;->c:Laq/t;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Laq/t;->h()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Ldu/c;->c:Laq/t;

    .line 13
    .line 14
    invoke-virtual {v0}, Laq/t;->i()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception v0

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    :goto_0
    iget-object v0, p0, Ldu/c;->a:Ljava/util/concurrent/Executor;

    .line 24
    .line 25
    iget-object v1, p0, Ldu/c;->b:Ldu/o;

    .line 26
    .line 27
    new-instance v2, Lbm/x;

    .line 28
    .line 29
    const/4 v3, 0x2

    .line 30
    invoke-direct {v2, v1, v3}, Lbm/x;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v0, v2}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iput-object v0, p0, Ldu/c;->c:Laq/t;

    .line 38
    .line 39
    :cond_1
    iget-object v0, p0, Ldu/c;->c:Laq/t;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    monitor-exit p0

    .line 42
    return-object v0

    .line 43
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    throw v0
.end method

.method public final c()Ldu/e;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ldu/c;->c:Laq/t;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Laq/t;->i()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Ldu/c;->c:Laq/t;

    .line 13
    .line 14
    invoke-virtual {v0}, Laq/t;->g()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Ldu/e;

    .line 19
    .line 20
    monitor-exit p0

    .line 21
    return-object v0

    .line 22
    :catchall_0
    move-exception v0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    :try_start_1
    invoke-virtual {p0}, Ldu/c;->b()Laq/j;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 30
    .line 31
    invoke-static {p0}, Ldu/c;->a(Laq/j;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    check-cast p0, Ldu/e;
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_1 .. :try_end_1} :catch_0

    .line 36
    .line 37
    return-object p0

    .line 38
    :catch_0
    move-exception p0

    .line 39
    const-string v0, "FirebaseRemoteConfig"

    .line 40
    .line 41
    const-string v1, "Reading from storage file failed."

    .line 42
    .line 43
    invoke-static {v0, v1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 44
    .line 45
    .line 46
    const/4 p0, 0x0

    .line 47
    return-object p0

    .line 48
    :goto_0
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 49
    throw v0
.end method

.method public final d(Ldu/e;)Laq/t;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/h;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1, p0, p1}, Lcom/google/firebase/messaging/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Ldu/c;->a:Ljava/util/concurrent/Executor;

    .line 8
    .line 9
    invoke-static {v1, v0}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v2, La0/h;

    .line 14
    .line 15
    const/16 v3, 0xa

    .line 16
    .line 17
    invoke-direct {v2, v3, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v1, v2}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method
