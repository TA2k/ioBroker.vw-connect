.class public final Lxt/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lst/a;


# instance fields
.field public final a:Ljava/util/concurrent/ScheduledExecutorService;

.field public final b:Ljava/util/concurrent/ConcurrentLinkedQueue;

.field public final c:Ljava/lang/Runtime;

.field public d:Ljava/util/concurrent/ScheduledFuture;

.field public e:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lxt/f;->f:Lst/a;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadScheduledExecutor()Ljava/util/concurrent/ScheduledExecutorService;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    iput-object v2, p0, Lxt/f;->d:Ljava/util/concurrent/ScheduledFuture;

    .line 14
    .line 15
    const-wide/16 v2, -0x1

    .line 16
    .line 17
    iput-wide v2, p0, Lxt/f;->e:J

    .line 18
    .line 19
    iput-object v0, p0, Lxt/f;->a:Ljava/util/concurrent/ScheduledExecutorService;

    .line 20
    .line 21
    new-instance v0, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 22
    .line 23
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lxt/f;->b:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 27
    .line 28
    iput-object v1, p0, Lxt/f;->c:Ljava/lang/Runtime;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final declared-synchronized a(JLzt/h;)V
    .locals 9

    .line 1
    const-string v1, "Unable to start collecting Memory Metrics: "

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iput-wide p1, p0, Lxt/f;->e:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    :try_start_1
    iget-object v2, p0, Lxt/f;->a:Ljava/util/concurrent/ScheduledExecutorService;

    .line 7
    .line 8
    new-instance v3, Lxt/e;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-direct {v3, p0, p3, v0}, Lxt/e;-><init>(Lxt/f;Lzt/h;I)V

    .line 12
    .line 13
    .line 14
    sget-object v8, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 15
    .line 16
    const-wide/16 v4, 0x0

    .line 17
    .line 18
    move-wide v6, p1

    .line 19
    invoke-interface/range {v2 .. v8}, Ljava/util/concurrent/ScheduledExecutorService;->scheduleAtFixedRate(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lxt/f;->d:Ljava/util/concurrent/ScheduledFuture;
    :try_end_1
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception v0

    .line 27
    move-object p1, v0

    .line 28
    goto :goto_1

    .line 29
    :catch_0
    move-exception v0

    .line 30
    move-object p1, v0

    .line 31
    :try_start_2
    sget-object p2, Lxt/f;->f:Lst/a;

    .line 32
    .line 33
    new-instance p3, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    invoke-direct {p3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p2, p1}, Lst/a;->f(Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 50
    .line 51
    .line 52
    :goto_0
    monitor-exit p0

    .line 53
    return-void

    .line 54
    :goto_1
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 55
    throw p1
.end method

.method public final b(Lzt/h;)Lau/d;
    .locals 4

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    iget-wide v0, p1, Lzt/h;->d:J

    .line 6
    .line 7
    invoke-virtual {p1}, Lzt/h;->j()J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    add-long/2addr v2, v0

    .line 12
    invoke-static {}, Lau/d;->u()Lau/c;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p1}, Lcom/google/protobuf/n;->j()V

    .line 17
    .line 18
    .line 19
    iget-object v0, p1, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 20
    .line 21
    check-cast v0, Lau/d;

    .line 22
    .line 23
    invoke-static {v0, v2, v3}, Lau/d;->s(Lau/d;J)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lxt/f;->c:Ljava/lang/Runtime;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Runtime;->totalMemory()J

    .line 29
    .line 30
    .line 31
    move-result-wide v0

    .line 32
    invoke-virtual {p0}, Ljava/lang/Runtime;->freeMemory()J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    sub-long/2addr v0, v2

    .line 37
    const/4 p0, 0x5

    .line 38
    invoke-static {p0}, Lz9/c;->a(I)J

    .line 39
    .line 40
    .line 41
    move-result-wide v2

    .line 42
    mul-long/2addr v2, v0

    .line 43
    const-wide/16 v0, 0x400

    .line 44
    .line 45
    div-long/2addr v2, v0

    .line 46
    invoke-static {v2, v3}, Ljp/m1;->j(J)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    invoke-virtual {p1}, Lcom/google/protobuf/n;->j()V

    .line 51
    .line 52
    .line 53
    iget-object v0, p1, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 54
    .line 55
    check-cast v0, Lau/d;

    .line 56
    .line 57
    invoke-static {v0, p0}, Lau/d;->t(Lau/d;I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Lau/d;

    .line 65
    .line 66
    return-object p0
.end method
