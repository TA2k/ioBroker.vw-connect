.class public final Lu/x;
.super Landroid/hardware/camera2/CameraDevice$StateCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lj0/h;

.field public final b:Lj0/c;

.field public c:Landroidx/lifecycle/a1;

.field public d:Ljava/util/concurrent/ScheduledFuture;

.field public final e:Las/e;

.field public final synthetic f:Lu/y;


# direct methods
.method public constructor <init>(Lu/y;Lj0/h;Lj0/c;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lu/x;->f:Lu/y;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/hardware/camera2/CameraDevice$StateCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lu/x;->a:Lj0/h;

    .line 7
    .line 8
    iput-object p3, p0, Lu/x;->b:Lj0/c;

    .line 9
    .line 10
    new-instance p1, Las/e;

    .line 11
    .line 12
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p0, p1, Las/e;->c:Ljava/lang/Object;

    .line 16
    .line 17
    const-wide/16 p2, -0x1

    .line 18
    .line 19
    iput-wide p2, p1, Las/e;->b:J

    .line 20
    .line 21
    iput-wide p4, p1, Las/e;->a:J

    .line 22
    .line 23
    iput-object p1, p0, Lu/x;->e:Las/e;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lu/x;->d:Ljava/util/concurrent/ScheduledFuture;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v2, "Cancelling scheduled re-open: "

    .line 9
    .line 10
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v2, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 14
    .line 15
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iget-object v2, p0, Lu/x;->f:Lu/y;

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    invoke-virtual {v2, v0, v3}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    iput-boolean v2, v0, Landroidx/lifecycle/a1;->e:Z

    .line 32
    .line 33
    iput-object v3, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 34
    .line 35
    iget-object v0, p0, Lu/x;->d:Ljava/util/concurrent/ScheduledFuture;

    .line 36
    .line 37
    invoke-interface {v0, v1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 38
    .line 39
    .line 40
    iput-object v3, p0, Lu/x;->d:Ljava/util/concurrent/ScheduledFuture;

    .line 41
    .line 42
    return v2

    .line 43
    :cond_0
    return v1
.end method

.method public final b()V
    .locals 10

    .line 1
    iget-object v0, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    move v0, v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v2

    .line 10
    :goto_0
    const/4 v3, 0x0

    .line 11
    invoke-static {v3, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lu/x;->d:Ljava/util/concurrent/ScheduledFuture;

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move v1, v2

    .line 20
    :goto_1
    invoke-static {v3, v1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lu/x;->e:Las/e;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 29
    .line 30
    .line 31
    move-result-wide v4

    .line 32
    iget-wide v6, v0, Las/e;->b:J

    .line 33
    .line 34
    const-wide/16 v8, -0x1

    .line 35
    .line 36
    cmp-long v1, v6, v8

    .line 37
    .line 38
    if-nez v1, :cond_2

    .line 39
    .line 40
    iput-wide v4, v0, Las/e;->b:J

    .line 41
    .line 42
    :cond_2
    iget-wide v6, v0, Las/e;->b:J

    .line 43
    .line 44
    sub-long/2addr v4, v6

    .line 45
    invoke-virtual {v0}, Las/e;->b()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    int-to-long v6, v1

    .line 50
    cmp-long v1, v4, v6

    .line 51
    .line 52
    iget-object v4, p0, Lu/x;->f:Lu/y;

    .line 53
    .line 54
    if-ltz v1, :cond_3

    .line 55
    .line 56
    iput-wide v8, v0, Las/e;->b:J

    .line 57
    .line 58
    new-instance p0, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v1, "Camera reopening attempted for "

    .line 61
    .line 62
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Las/e;->b()I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v0, "ms without success."

    .line 73
    .line 74
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    const-string v0, "Camera2CameraImpl"

    .line 82
    .line 83
    invoke-static {v0, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const/4 p0, 0x4

    .line 87
    invoke-virtual {v4, p0, v3, v2}, Lu/y;->H(ILb0/e;Z)V

    .line 88
    .line 89
    .line 90
    return-void

    .line 91
    :cond_3
    new-instance v1, Landroidx/lifecycle/a1;

    .line 92
    .line 93
    iget-object v2, p0, Lu/x;->a:Lj0/h;

    .line 94
    .line 95
    invoke-direct {v1, p0, v2}, Landroidx/lifecycle/a1;-><init>(Lu/x;Lj0/h;)V

    .line 96
    .line 97
    .line 98
    iput-object v1, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 99
    .line 100
    new-instance v1, Ljava/lang/StringBuilder;

    .line 101
    .line 102
    const-string v2, "Attempting camera re-open in "

    .line 103
    .line 104
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Las/e;->a()I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string v2, "ms: "

    .line 115
    .line 116
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    iget-object v2, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 120
    .line 121
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string v2, " activeResuming = "

    .line 125
    .line 126
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    iget-boolean v2, v4, Lu/y;->J:Z

    .line 130
    .line 131
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-virtual {v4, v1, v3}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 139
    .line 140
    .line 141
    iget-object v1, p0, Lu/x;->c:Landroidx/lifecycle/a1;

    .line 142
    .line 143
    invoke-virtual {v0}, Las/e;->a()I

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    int-to-long v2, v0

    .line 148
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 149
    .line 150
    iget-object v4, p0, Lu/x;->b:Lj0/c;

    .line 151
    .line 152
    invoke-virtual {v4, v1, v2, v3, v0}, Lj0/c;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    iput-object v0, p0, Lu/x;->d:Ljava/util/concurrent/ScheduledFuture;

    .line 157
    .line 158
    return-void
.end method

.method public final c()Z
    .locals 2

    .line 1
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 2
    .line 3
    iget-boolean v0, p0, Lu/y;->J:Z

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget p0, p0, Lu/y;->n:I

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_0

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-ne p0, v1, :cond_1

    .line 14
    .line 15
    :cond_0
    return v0

    .line 16
    :cond_1
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public final onClosed(Landroid/hardware/camera2/CameraDevice;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 2
    .line 3
    const-string v1, "CameraDevice.onClosed()"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-virtual {v0, v1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 10
    .line 11
    iget-object v0, v0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v3, 0x1

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    move v0, v3

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v0, v1

    .line 20
    :goto_0
    new-instance v4, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v5, "Unexpected onClose callback on camera device: "

    .line 23
    .line 24
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-static {p1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Lu/x;->f:Lu/y;

    .line 38
    .line 39
    iget p1, p1, Lu/y;->O:I

    .line 40
    .line 41
    invoke-static {p1}, Lu/w;->o(I)I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eq p1, v3, :cond_4

    .line 46
    .line 47
    const/4 v0, 0x5

    .line 48
    if-eq p1, v0, :cond_4

    .line 49
    .line 50
    const/4 v0, 0x6

    .line 51
    if-eq p1, v0, :cond_2

    .line 52
    .line 53
    const/4 v0, 0x7

    .line 54
    if-ne p1, v0, :cond_1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 60
    .line 61
    iget p0, p0, Lu/y;->O:I

    .line 62
    .line 63
    invoke-static {p0}, Lu/w;->p(I)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-string v0, "Camera closed while in state: "

    .line 68
    .line 69
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p1

    .line 77
    :cond_2
    :goto_1
    iget-object p1, p0, Lu/x;->f:Lu/y;

    .line 78
    .line 79
    iget v0, p1, Lu/y;->n:I

    .line 80
    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    invoke-static {v0}, Lu/y;->y(I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    const-string v1, "Camera closed due to error: "

    .line 88
    .line 89
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-virtual {p1, v0, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0}, Lu/x;->b()V

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :cond_3
    invoke-virtual {p1, v1}, Lu/y;->L(Z)V

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :cond_4
    iget-object p1, p0, Lu/x;->f:Lu/y;

    .line 105
    .line 106
    iget-object p1, p1, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 107
    .line 108
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    invoke-static {v2, p1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 113
    .line 114
    .line 115
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 116
    .line 117
    invoke-virtual {p0}, Lu/y;->u()V

    .line 118
    .line 119
    .line 120
    return-void
.end method

.method public final onDisconnected(Landroid/hardware/camera2/CameraDevice;)V
    .locals 3

    .line 1
    const-string v0, "CameraDevice.onDisconnected()"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lu/x;->f:Lu/y;

    .line 5
    .line 6
    invoke-virtual {v2, v0, v1}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-virtual {p0, p1, v0}, Lu/x;->onError(Landroid/hardware/camera2/CameraDevice;I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final onError(Landroid/hardware/camera2/CameraDevice;I)V
    .locals 11

    .line 1
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 2
    .line 3
    iput-object p1, v0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 4
    .line 5
    iput p2, v0, Lu/y;->n:I

    .line 6
    .line 7
    iget-object v0, v0, Lu/y;->N:Lb81/b;

    .line 8
    .line 9
    iget-object v1, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lu/y;

    .line 12
    .line 13
    const-string v2, "Camera receive onErrorCallback"

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-virtual {v1, v2, v3}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Lb81/b;->j()V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 23
    .line 24
    iget v0, v0, Lu/y;->O:I

    .line 25
    .line 26
    invoke-static {v0}, Lu/w;->o(I)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const-string v1, " while in "

    .line 31
    .line 32
    const-string v2, " failed with "

    .line 33
    .line 34
    const-string v4, "CameraDevice.onError(): "

    .line 35
    .line 36
    const-string v5, "Camera2CameraImpl"

    .line 37
    .line 38
    const/4 v6, 0x1

    .line 39
    if-eq v0, v6, :cond_7

    .line 40
    .line 41
    packed-switch v0, :pswitch_data_0

    .line 42
    .line 43
    .line 44
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 47
    .line 48
    iget p0, p0, Lu/y;->O:I

    .line 49
    .line 50
    invoke-static {p0}, Lu/w;->p(I)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    const-string p2, "onError() should not be possible from state: "

    .line 55
    .line 56
    invoke-virtual {p2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p1

    .line 64
    :pswitch_0
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-static {p2}, Lu/y;->y(I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    iget-object v8, p0, Lu/x;->f:Lu/y;

    .line 73
    .line 74
    iget v8, v8, Lu/y;->O:I

    .line 75
    .line 76
    invoke-static {v8}, Lu/w;->n(I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v8

    .line 80
    invoke-static {v4, v0, v2, v7, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v1, " state. Will attempt recovering from error."

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-static {v5, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 100
    .line 101
    iget v0, v0, Lu/y;->O:I

    .line 102
    .line 103
    const/16 v1, 0x9

    .line 104
    .line 105
    const/4 v2, 0x0

    .line 106
    const/16 v4, 0x8

    .line 107
    .line 108
    if-eq v0, v1, :cond_1

    .line 109
    .line 110
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 111
    .line 112
    iget v0, v0, Lu/y;->O:I

    .line 113
    .line 114
    const/16 v1, 0xa

    .line 115
    .line 116
    if-eq v0, v1, :cond_1

    .line 117
    .line 118
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 119
    .line 120
    iget v0, v0, Lu/y;->O:I

    .line 121
    .line 122
    const/16 v1, 0xb

    .line 123
    .line 124
    if-eq v0, v1, :cond_1

    .line 125
    .line 126
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 127
    .line 128
    iget v0, v0, Lu/y;->O:I

    .line 129
    .line 130
    if-eq v0, v4, :cond_1

    .line 131
    .line 132
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 133
    .line 134
    iget v0, v0, Lu/y;->O:I

    .line 135
    .line 136
    const/4 v1, 0x7

    .line 137
    if-ne v0, v1, :cond_0

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_0
    move v0, v2

    .line 141
    goto :goto_1

    .line 142
    :cond_1
    :goto_0
    move v0, v6

    .line 143
    :goto_1
    iget-object v1, p0, Lu/x;->f:Lu/y;

    .line 144
    .line 145
    iget v1, v1, Lu/y;->O:I

    .line 146
    .line 147
    invoke-static {v1}, Lu/w;->p(I)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    const-string v7, "Attempt to handle open error from non open state: "

    .line 152
    .line 153
    invoke-virtual {v7, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 158
    .line 159
    .line 160
    const/4 v0, 0x3

    .line 161
    const/4 v1, 0x2

    .line 162
    if-eq p2, v6, :cond_3

    .line 163
    .line 164
    if-eq p2, v1, :cond_3

    .line 165
    .line 166
    const/4 v7, 0x4

    .line 167
    if-eq p2, v7, :cond_3

    .line 168
    .line 169
    new-instance v1, Ljava/lang/StringBuilder;

    .line 170
    .line 171
    const-string v2, "Error observed on open (or opening) camera device "

    .line 172
    .line 173
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string p1, ": "

    .line 184
    .line 185
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-static {p2}, Lu/y;->y(I)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    const-string p1, " closing camera."

    .line 196
    .line 197
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    invoke-static {v5, p1}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    const/4 p1, 0x6

    .line 208
    if-ne p2, v0, :cond_2

    .line 209
    .line 210
    const/4 p2, 0x5

    .line 211
    goto :goto_2

    .line 212
    :cond_2
    move p2, p1

    .line 213
    :goto_2
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 214
    .line 215
    new-instance v1, Lb0/e;

    .line 216
    .line 217
    invoke-direct {v1, p2, v3}, Lb0/e;-><init>(ILjava/lang/Throwable;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v0, p1, v1, v6}, Lu/y;->H(ILb0/e;Z)V

    .line 221
    .line 222
    .line 223
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 224
    .line 225
    invoke-virtual {p0}, Lu/y;->t()V

    .line 226
    .line 227
    .line 228
    return-void

    .line 229
    :cond_3
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    invoke-static {p2}, Lu/y;->y(I)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v7

    .line 237
    const-string v8, "] after error["

    .line 238
    .line 239
    const-string v9, "]"

    .line 240
    .line 241
    const-string v10, "Attempt to reopen camera["

    .line 242
    .line 243
    invoke-static {v10, p1, v8, v7, v9}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object p1

    .line 247
    invoke-static {v5, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 251
    .line 252
    iget p1, p0, Lu/y;->n:I

    .line 253
    .line 254
    if-eqz p1, :cond_4

    .line 255
    .line 256
    move v2, v6

    .line 257
    :cond_4
    const-string p1, "Can only reopen camera device after error if the camera device is actually in an error state."

    .line 258
    .line 259
    invoke-static {p1, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 260
    .line 261
    .line 262
    if-eq p2, v6, :cond_6

    .line 263
    .line 264
    if-eq p2, v1, :cond_5

    .line 265
    .line 266
    goto :goto_3

    .line 267
    :cond_5
    move v0, v6

    .line 268
    goto :goto_3

    .line 269
    :cond_6
    move v0, v1

    .line 270
    :goto_3
    new-instance p1, Lb0/e;

    .line 271
    .line 272
    invoke-direct {p1, v0, v3}, Lb0/e;-><init>(ILjava/lang/Throwable;)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {p0, v4, p1, v6}, Lu/y;->H(ILb0/e;Z)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {p0}, Lu/y;->t()V

    .line 279
    .line 280
    .line 281
    return-void

    .line 282
    :cond_7
    :pswitch_1
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 283
    .line 284
    .line 285
    move-result-object p1

    .line 286
    invoke-static {p2}, Lu/y;->y(I)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object p2

    .line 290
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 291
    .line 292
    iget v0, v0, Lu/y;->O:I

    .line 293
    .line 294
    invoke-static {v0}, Lu/w;->n(I)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    invoke-static {v4, p1, v2, p2, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    move-result-object p1

    .line 302
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 303
    .line 304
    .line 305
    const-string p2, " state. Will finish closing camera."

    .line 306
    .line 307
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 308
    .line 309
    .line 310
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object p1

    .line 314
    invoke-static {v5, p1}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 318
    .line 319
    invoke-virtual {p0}, Lu/y;->t()V

    .line 320
    .line 321
    .line 322
    return-void

    .line 323
    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final onOpened(Landroid/hardware/camera2/CameraDevice;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 2
    .line 3
    const-string v1, "CameraDevice.onOpened()"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-virtual {v0, v1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 10
    .line 11
    iput-object p1, v0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    iput v1, v0, Lu/y;->n:I

    .line 15
    .line 16
    iget-object v1, p0, Lu/x;->e:Las/e;

    .line 17
    .line 18
    const-wide/16 v3, -0x1

    .line 19
    .line 20
    iput-wide v3, v1, Las/e;->b:J

    .line 21
    .line 22
    iget v0, v0, Lu/y;->O:I

    .line 23
    .line 24
    invoke-static {v0}, Lu/w;->o(I)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v1, 0x1

    .line 29
    if-eq v0, v1, :cond_3

    .line 30
    .line 31
    const/4 v1, 0x5

    .line 32
    if-eq v0, v1, :cond_3

    .line 33
    .line 34
    const/4 v1, 0x6

    .line 35
    if-eq v0, v1, :cond_1

    .line 36
    .line 37
    const/4 v1, 0x7

    .line 38
    if-eq v0, v1, :cond_1

    .line 39
    .line 40
    const/16 v1, 0x8

    .line 41
    .line 42
    if-ne v0, v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 48
    .line 49
    iget p0, p0, Lu/y;->O:I

    .line 50
    .line 51
    invoke-static {p0}, Lu/w;->p(I)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    const-string v0, "onOpened() should not be possible from state: "

    .line 56
    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1

    .line 65
    :cond_1
    :goto_0
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 66
    .line 67
    const/16 v1, 0xa

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Lu/y;->G(I)V

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Lu/x;->f:Lu/y;

    .line 73
    .line 74
    iget-object v0, v0, Lu/y;->w:Lh0/k0;

    .line 75
    .line 76
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iget-object v1, p0, Lu/x;->f:Lu/y;

    .line 81
    .line 82
    iget-object v2, v1, Lu/y;->v:Lz/a;

    .line 83
    .line 84
    iget-object v1, v1, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 85
    .line 86
    invoke-virtual {v1}, Landroid/hardware/camera2/CameraDevice;->getId()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v2, v1}, Lz/a;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0, p1, v1}, Lh0/k0;->e(Ljava/lang/String;Ljava/lang/String;)Z

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    if-eqz p1, :cond_2

    .line 99
    .line 100
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 101
    .line 102
    invoke-virtual {p0}, Lu/y;->E()V

    .line 103
    .line 104
    .line 105
    :cond_2
    return-void

    .line 106
    :cond_3
    iget-object p1, p0, Lu/x;->f:Lu/y;

    .line 107
    .line 108
    iget-object p1, p1, Lu/y;->s:Ljava/util/LinkedHashMap;

    .line 109
    .line 110
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 111
    .line 112
    .line 113
    move-result p1

    .line 114
    invoke-static {v2, p1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 115
    .line 116
    .line 117
    iget-object p1, p0, Lu/x;->f:Lu/y;

    .line 118
    .line 119
    iget-object p1, p1, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 120
    .line 121
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraDevice;->close()V

    .line 122
    .line 123
    .line 124
    iget-object p0, p0, Lu/x;->f:Lu/y;

    .line 125
    .line 126
    iput-object v2, p0, Lu/y;->m:Landroid/hardware/camera2/CameraDevice;

    .line 127
    .line 128
    return-void
.end method
