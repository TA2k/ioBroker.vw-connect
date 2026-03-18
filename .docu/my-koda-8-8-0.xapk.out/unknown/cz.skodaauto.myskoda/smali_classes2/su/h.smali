.class public final Lsu/h;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public b:Lsu/g;

.field public final synthetic c:Lsu/i;


# direct methods
.method public constructor <init>(Lsu/i;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lsu/h;->c:Lsu/i;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/Handler;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-boolean p1, p0, Lsu/h;->a:Z

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    iput-object p1, p0, Lsu/h;->b:Lsu/g;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)V
    .locals 6

    .line 1
    iget p1, p1, Landroid/os/Message;->what:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    if-ne p1, v1, :cond_0

    .line 6
    .line 7
    iput-boolean v0, p0, Lsu/h;->a:Z

    .line 8
    .line 9
    iget-object p1, p0, Lsu/h;->b:Lsu/g;

    .line 10
    .line 11
    if-eqz p1, :cond_2

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p0, v0}, Landroid/os/Handler;->removeMessages(I)V

    .line 18
    .line 19
    .line 20
    iget-boolean p1, p0, Lsu/h;->a:Z

    .line 21
    .line 22
    if-eqz p1, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    iget-object p1, p0, Lsu/h;->b:Lsu/g;

    .line 26
    .line 27
    if-nez p1, :cond_3

    .line 28
    .line 29
    :cond_2
    :goto_0
    return-void

    .line 30
    :cond_3
    iget-object p1, p0, Lsu/h;->c:Lsu/i;

    .line 31
    .line 32
    iget-object p1, p1, Lsu/i;->a:Lqp/g;

    .line 33
    .line 34
    invoke-virtual {p1}, Lqp/g;->c()Lj1/a;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    monitor-enter p0

    .line 39
    :try_start_0
    iget-object v0, p0, Lsu/h;->b:Lsu/g;

    .line 40
    .line 41
    const/4 v2, 0x0

    .line 42
    iput-object v2, p0, Lsu/h;->b:Lsu/g;

    .line 43
    .line 44
    iput-boolean v1, p0, Lsu/h;->a:Z

    .line 45
    .line 46
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    new-instance v1, Lm8/o;

    .line 48
    .line 49
    const/16 v2, 0xc

    .line 50
    .line 51
    invoke-direct {v1, p0, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    iput-object v1, v0, Lsu/g;->e:Lm8/o;

    .line 55
    .line 56
    iput-object p1, v0, Lsu/g;->f:Lj1/a;

    .line 57
    .line 58
    iget-object p1, p0, Lsu/h;->c:Lsu/i;

    .line 59
    .line 60
    iget-object p1, p1, Lsu/i;->a:Lqp/g;

    .line 61
    .line 62
    invoke-virtual {p1}, Lqp/g;->b()Lcom/google/android/gms/maps/model/CameraPosition;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iget p1, p1, Lcom/google/android/gms/maps/model/CameraPosition;->e:F

    .line 67
    .line 68
    iput p1, v0, Lsu/g;->h:F

    .line 69
    .line 70
    new-instance v1, Lyu/b;

    .line 71
    .line 72
    iget-object v2, v0, Lsu/g;->i:Lsu/i;

    .line 73
    .line 74
    iget v2, v2, Lsu/i;->n:F

    .line 75
    .line 76
    invoke-static {p1, v2}, Ljava/lang/Math;->min(FF)F

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    float-to-double v2, p1

    .line 81
    const-wide/high16 v4, 0x4000000000000000L    # 2.0

    .line 82
    .line 83
    invoke-static {v4, v5, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 84
    .line 85
    .line 86
    move-result-wide v2

    .line 87
    const-wide/high16 v4, 0x4070000000000000L    # 256.0

    .line 88
    .line 89
    mul-double/2addr v2, v4

    .line 90
    invoke-direct {v1, v2, v3}, Lyu/b;-><init>(D)V

    .line 91
    .line 92
    .line 93
    iput-object v1, v0, Lsu/g;->g:Lyu/b;

    .line 94
    .line 95
    iget-object p0, p0, Lsu/h;->c:Lsu/i;

    .line 96
    .line 97
    iget-object p0, p0, Lsu/i;->f:Ljava/util/concurrent/ExecutorService;

    .line 98
    .line 99
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 100
    .line 101
    .line 102
    return-void

    .line 103
    :catchall_0
    move-exception p1

    .line 104
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 105
    throw p1
.end method
