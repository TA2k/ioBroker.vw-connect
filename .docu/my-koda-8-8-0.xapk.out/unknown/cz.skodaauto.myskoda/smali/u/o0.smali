.class public final Lu/o0;
.super Lu/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/List;I)V
    .locals 1

    iput p2, p0, Lu/o0;->a:I

    packed-switch p2, :pswitch_data_0

    .line 1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_0

    .line 2
    new-instance p1, Lu/i0;

    .line 3
    invoke-direct {p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;-><init>()V

    goto :goto_0

    .line 4
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p2

    const/4 v0, 0x1

    if-ne p2, v0, :cond_1

    const/4 p2, 0x0

    .line 5
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    goto :goto_0

    .line 6
    :cond_1
    new-instance p2, Lu/h0;

    invoke-direct {p2, p1}, Lu/h0;-><init>(Ljava/util/List;)V

    move-object p1, p2

    .line 7
    :goto_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lu/o0;->b:Ljava/lang/Object;

    return-void

    .line 9
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 11
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lu/p0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lu/o0;->a:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Lu/o0;->b:Ljava/lang/Object;

    return-void
.end method

.method private final i(Lu/g1;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public a(Lu/g1;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lu/d1;

    .line 26
    .line 27
    invoke-virtual {v0, p1}, Lu/d1;->a(Lu/g1;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void

    .line 32
    :pswitch_1
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 35
    .line 36
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Lb81/c;

    .line 43
    .line 44
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onActive(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lu/g1;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lu/d1;

    .line 26
    .line 27
    invoke-virtual {v0, p1}, Lu/d1;->b(Lu/g1;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void

    .line 32
    :pswitch_1
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 35
    .line 36
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Lb81/c;

    .line 43
    .line 44
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onCaptureQueueEmpty(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c(Lu/g1;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lu/d1;

    .line 26
    .line 27
    invoke-virtual {v0, p1}, Lu/d1;->c(Lu/g1;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void

    .line 32
    :pswitch_1
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 35
    .line 36
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Lb81/c;

    .line 43
    .line 44
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onClosed(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Lu/g1;)V
    .locals 3

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lu/d1;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Lu/d1;->d(Lu/g1;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-void

    .line 31
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 34
    .line 35
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Lb81/c;

    .line 42
    .line 43
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onConfigureFailed(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_1
    const-string p1, "onConfigureFailed() should not be possible in state: "

    .line 52
    .line 53
    const-string v0, "CameraCaptureSession.onConfigureFailed() "

    .line 54
    .line 55
    iget-object v1, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v1, Lu/p0;

    .line 58
    .line 59
    iget-object v1, v1, Lu/p0;->a:Ljava/lang/Object;

    .line 60
    .line 61
    monitor-enter v1

    .line 62
    :try_start_0
    iget-object v2, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v2, Lu/p0;

    .line 65
    .line 66
    iget v2, v2, Lu/p0;->j:I

    .line 67
    .line 68
    invoke-static {v2}, Lu/w;->o(I)I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    packed-switch v2, :pswitch_data_1

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :pswitch_2
    iget-object p1, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p1, Lu/p0;

    .line 79
    .line 80
    invoke-virtual {p1}, Lu/p0;->e()V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :catchall_0
    move-exception p0

    .line 85
    goto :goto_2

    .line 86
    :pswitch_3
    const-string p1, "CaptureSession"

    .line 87
    .line 88
    const-string v2, "ConfigureFailed callback after change to RELEASED state"

    .line 89
    .line 90
    invoke-static {p1, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :goto_1
    const-string p1, "CaptureSession"

    .line 94
    .line 95
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p0, Lu/p0;

    .line 98
    .line 99
    iget p0, p0, Lu/p0;->j:I

    .line 100
    .line 101
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    monitor-exit v1

    .line 113
    return-void

    .line 114
    :pswitch_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 115
    .line 116
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p0, Lu/p0;

    .line 119
    .line 120
    iget p0, p0, Lu/p0;->j:I

    .line 121
    .line 122
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw v0

    .line 134
    :goto_2
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 135
    throw p0

    .line 136
    nop

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 138
    .line 139
    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    .line 145
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_4
        :pswitch_4
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_4
    .end packed-switch
.end method

.method public final e(Lu/g1;)V
    .locals 5

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lu/d1;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Lu/d1;->e(Lu/g1;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-void

    .line 31
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 34
    .line 35
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Lb81/c;

    .line 42
    .line 43
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onConfigured(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_1
    const-string v0, "onConfigured() should not be possible in state: "

    .line 52
    .line 53
    const-string v1, "CameraCaptureSession.onConfigured() mState="

    .line 54
    .line 55
    iget-object v2, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v2, Lu/p0;

    .line 58
    .line 59
    iget-object v2, v2, Lu/p0;->a:Ljava/lang/Object;

    .line 60
    .line 61
    monitor-enter v2

    .line 62
    :try_start_0
    iget-object v3, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v3, Lu/p0;

    .line 65
    .line 66
    iget v3, v3, Lu/p0;->j:I

    .line 67
    .line 68
    invoke-static {v3}, Lu/w;->o(I)I

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    packed-switch v3, :pswitch_data_1

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :pswitch_2
    iget-object v0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v0, Lu/p0;

    .line 79
    .line 80
    const/16 v3, 0x8

    .line 81
    .line 82
    invoke-virtual {v0, v3}, Lu/p0;->p(I)V

    .line 83
    .line 84
    .line 85
    iget-object v0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v0, Lu/p0;

    .line 88
    .line 89
    iput-object p1, v0, Lu/p0;->e:Lu/g1;

    .line 90
    .line 91
    const-string p1, "CaptureSession"

    .line 92
    .line 93
    const-string v0, "Attempting to send capture request onConfigured"

    .line 94
    .line 95
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    iget-object p1, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p1, Lu/p0;

    .line 101
    .line 102
    iget-object v0, p1, Lu/p0;->f:Lh0/z1;

    .line 103
    .line 104
    invoke-virtual {p1, v0}, Lu/p0;->l(Lh0/z1;)V

    .line 105
    .line 106
    .line 107
    iget-object p1, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast p1, Lu/p0;

    .line 110
    .line 111
    iget-object v0, p1, Lu/p0;->p:Lb6/f;

    .line 112
    .line 113
    invoke-virtual {v0}, Lb6/f;->m()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    new-instance v3, Lm8/o;

    .line 118
    .line 119
    const/16 v4, 0xf

    .line 120
    .line 121
    invoke-direct {v3, p1, v4}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 122
    .line 123
    .line 124
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-interface {v0, p1, v3}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :catchall_0
    move-exception p0

    .line 133
    goto :goto_2

    .line 134
    :pswitch_3
    iget-object v0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v0, Lu/p0;

    .line 137
    .line 138
    iput-object p1, v0, Lu/p0;->e:Lu/g1;

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :pswitch_4
    invoke-virtual {p1}, Lu/g1;->i()V

    .line 142
    .line 143
    .line 144
    :goto_1
    const-string p1, "CaptureSession"

    .line 145
    .line 146
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast p0, Lu/p0;

    .line 149
    .line 150
    iget p0, p0, Lu/p0;->j:I

    .line 151
    .line 152
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    invoke-static {p1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    monitor-exit v2

    .line 164
    return-void

    .line 165
    :pswitch_5
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 166
    .line 167
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast p0, Lu/p0;

    .line 170
    .line 171
    iget p0, p0, Lu/p0;->j:I

    .line 172
    .line 173
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p1

    .line 185
    :goto_2
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 186
    throw p0

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 188
    .line 189
    .line 190
    .line 191
    .line 192
    .line 193
    .line 194
    .line 195
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_5
    .end packed-switch
.end method

.method public final f(Lu/g1;)V
    .locals 3

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lu/d1;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Lu/d1;->f(Lu/g1;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-void

    .line 31
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 34
    .line 35
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Lb81/c;

    .line 42
    .line 43
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onReady(Landroid/hardware/camera2/CameraCaptureSession;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_1
    const-string p1, "onReady() should not be possible in state: "

    .line 52
    .line 53
    const-string v0, "CameraCaptureSession.onReady() "

    .line 54
    .line 55
    iget-object v1, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v1, Lu/p0;

    .line 58
    .line 59
    iget-object v1, v1, Lu/p0;->a:Ljava/lang/Object;

    .line 60
    .line 61
    monitor-enter v1

    .line 62
    :try_start_0
    iget-object v2, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v2, Lu/p0;

    .line 65
    .line 66
    iget v2, v2, Lu/p0;->j:I

    .line 67
    .line 68
    invoke-static {v2}, Lu/w;->o(I)I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_1

    .line 73
    .line 74
    const-string p1, "CaptureSession"

    .line 75
    .line 76
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Lu/p0;

    .line 79
    .line 80
    iget p0, p0, Lu/p0;->j:I

    .line 81
    .line 82
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-static {p1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    monitor-exit v1

    .line 94
    return-void

    .line 95
    :catchall_0
    move-exception p0

    .line 96
    goto :goto_1

    .line 97
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast p0, Lu/p0;

    .line 102
    .line 103
    iget p0, p0, Lu/p0;->j:I

    .line 104
    .line 105
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw v0

    .line 117
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 118
    throw p0

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final g(Lu/g1;)V
    .locals 3

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lu/d1;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Lu/d1;->g(Lu/g1;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    :pswitch_0
    return-void

    .line 31
    :pswitch_1
    const-string p1, "onSessionFinished() should not be possible in state: "

    .line 32
    .line 33
    iget-object v0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lu/p0;

    .line 36
    .line 37
    iget-object v0, v0, Lu/p0;->a:Ljava/lang/Object;

    .line 38
    .line 39
    monitor-enter v0

    .line 40
    :try_start_0
    iget-object v1, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lu/p0;

    .line 43
    .line 44
    iget v1, v1, Lu/p0;->j:I

    .line 45
    .line 46
    const/4 v2, 0x1

    .line 47
    if-eq v1, v2, :cond_1

    .line 48
    .line 49
    const-string p1, "CaptureSession"

    .line 50
    .line 51
    const-string v1, "onSessionFinished()"

    .line 52
    .line 53
    invoke-static {p1, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lu/p0;

    .line 59
    .line 60
    invoke-virtual {p0}, Lu/p0;->e()V

    .line 61
    .line 62
    .line 63
    monitor-exit v0

    .line 64
    return-void

    .line 65
    :catchall_0
    move-exception p0

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Lu/p0;

    .line 72
    .line 73
    iget p0, p0, Lu/p0;->j:I

    .line 74
    .line 75
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v1

    .line 87
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 88
    throw p0

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public h(Lu/g1;Landroid/view/Surface;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/o0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lu/d1;

    .line 26
    .line 27
    invoke-virtual {v0, p1, p2}, Lu/d1;->h(Lu/g1;Landroid/view/Surface;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void

    .line 32
    :pswitch_1
    iget-object p0, p0, Lu/o0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;

    .line 35
    .line 36
    invoke-virtual {p1}, Lu/g1;->r()Lro/f;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Lb81/c;

    .line 43
    .line 44
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 47
    .line 48
    invoke-virtual {p0, p1, p2}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onSurfacePrepared(Landroid/hardware/camera2/CameraCaptureSession;Landroid/view/Surface;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
