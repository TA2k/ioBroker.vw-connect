.class public final Las/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J

.field public b:J

.field public c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 2

    packed-switch p1, :pswitch_data_0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, 0x0

    .line 6
    iput-wide v0, p0, Las/e;->a:J

    const-wide/16 v0, -0x1

    .line 7
    iput-wide v0, p0, Las/e;->b:J

    .line 8
    new-instance p1, Lrb0/a;

    const/4 v0, 0x2

    .line 9
    invoke-direct {p1, v0}, Lrb0/a;-><init>(I)V

    .line 10
    iput-object p1, p0, Las/e;->c:Ljava/lang/Object;

    return-void

    .line 11
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    iput-wide v0, p0, Las/e;->a:J

    .line 13
    iput-wide v0, p0, Las/e;->b:J

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(JJLjava/util/concurrent/TimeUnit;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-wide p1, p0, Las/e;->a:J

    .line 3
    iput-wide p3, p0, Las/e;->b:J

    .line 4
    iput-object p5, p0, Las/e;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()I
    .locals 6

    .line 1
    iget-object v0, p0, Las/e;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lu/x;

    .line 4
    .line 5
    invoke-virtual {v0}, Lu/x;->c()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/16 p0, 0x2bc

    .line 12
    .line 13
    return p0

    .line 14
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    iget-wide v2, p0, Las/e;->b:J

    .line 19
    .line 20
    const-wide/16 v4, -0x1

    .line 21
    .line 22
    cmp-long v2, v2, v4

    .line 23
    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    iput-wide v0, p0, Las/e;->b:J

    .line 27
    .line 28
    :cond_1
    iget-wide v2, p0, Las/e;->b:J

    .line 29
    .line 30
    sub-long/2addr v0, v2

    .line 31
    const-wide/32 v2, 0x1d4c0

    .line 32
    .line 33
    .line 34
    cmp-long p0, v0, v2

    .line 35
    .line 36
    if-gtz p0, :cond_2

    .line 37
    .line 38
    const/16 p0, 0x3e8

    .line 39
    .line 40
    return p0

    .line 41
    :cond_2
    const-wide/32 v2, 0x493e0

    .line 42
    .line 43
    .line 44
    cmp-long p0, v0, v2

    .line 45
    .line 46
    if-gtz p0, :cond_3

    .line 47
    .line 48
    const/16 p0, 0x7d0

    .line 49
    .line 50
    return p0

    .line 51
    :cond_3
    const/16 p0, 0xfa0

    .line 52
    .line 53
    return p0
.end method

.method public b()I
    .locals 4

    .line 1
    iget-wide v0, p0, Las/e;->a:J

    .line 2
    .line 3
    iget-object p0, p0, Las/e;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lu/x;

    .line 6
    .line 7
    invoke-virtual {p0}, Lu/x;->c()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    const-wide/16 v2, 0x0

    .line 12
    .line 13
    if-nez p0, :cond_1

    .line 14
    .line 15
    cmp-long p0, v0, v2

    .line 16
    .line 17
    const/16 v2, 0x2710

    .line 18
    .line 19
    if-lez p0, :cond_0

    .line 20
    .line 21
    long-to-int p0, v0

    .line 22
    invoke-static {p0, v2}, Ljava/lang/Math;->min(II)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :cond_0
    return v2

    .line 28
    :cond_1
    cmp-long p0, v0, v2

    .line 29
    .line 30
    const v2, 0x1b7740

    .line 31
    .line 32
    .line 33
    if-lez p0, :cond_2

    .line 34
    .line 35
    long-to-int p0, v0

    .line 36
    invoke-static {p0, v2}, Ljava/lang/Math;->min(II)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0

    .line 41
    :cond_2
    return v2
.end method

.method public c(Ljava/lang/Exception;)V
    .locals 7

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-object v2, p0, Las/e;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/lang/Exception;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    iput-object p1, p0, Las/e;->c:Ljava/lang/Object;

    .line 12
    .line 13
    :cond_0
    iget-wide v2, p0, Las/e;->a:J

    .line 14
    .line 15
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    cmp-long v2, v2, v4

    .line 21
    .line 22
    if-nez v2, :cond_2

    .line 23
    .line 24
    sget-object v2, Lc8/y;->l0:Ljava/lang/Object;

    .line 25
    .line 26
    monitor-enter v2

    .line 27
    :try_start_0
    sget v3, Lc8/y;->n0:I

    .line 28
    .line 29
    if-lez v3, :cond_1

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v3, 0x0

    .line 34
    :goto_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    if-nez v3, :cond_2

    .line 36
    .line 37
    const-wide/16 v2, 0xc8

    .line 38
    .line 39
    add-long/2addr v2, v0

    .line 40
    iput-wide v2, p0, Las/e;->a:J

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    throw p0

    .line 46
    :cond_2
    :goto_1
    iget-wide v2, p0, Las/e;->a:J

    .line 47
    .line 48
    cmp-long v6, v2, v4

    .line 49
    .line 50
    if-eqz v6, :cond_4

    .line 51
    .line 52
    cmp-long v2, v0, v2

    .line 53
    .line 54
    if-ltz v2, :cond_4

    .line 55
    .line 56
    iget-object v0, p0, Las/e;->c:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Ljava/lang/Exception;

    .line 59
    .line 60
    if-eq v0, p1, :cond_3

    .line 61
    .line 62
    invoke-virtual {v0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    :cond_3
    iget-object p1, p0, Las/e;->c:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p1, Ljava/lang/Exception;

    .line 68
    .line 69
    const/4 v0, 0x0

    .line 70
    iput-object v0, p0, Las/e;->c:Ljava/lang/Object;

    .line 71
    .line 72
    iput-wide v4, p0, Las/e;->a:J

    .line 73
    .line 74
    iput-wide v4, p0, Las/e;->b:J

    .line 75
    .line 76
    throw p1

    .line 77
    :cond_4
    const-wide/16 v2, 0x32

    .line 78
    .line 79
    add-long/2addr v0, v2

    .line 80
    iput-wide v0, p0, Las/e;->b:J

    .line 81
    .line 82
    return-void
.end method
