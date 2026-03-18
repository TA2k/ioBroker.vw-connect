.class public final Lw0/p;
.super Landroidx/core/app/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public e:Landroid/view/SurfaceView;

.field public final f:Lw0/o;


# direct methods
.method public constructor <init>(Landroid/widget/FrameLayout;Lw0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Landroidx/core/app/a0;-><init>(Landroid/widget/FrameLayout;Lw0/d;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Lw0/o;

    .line 5
    .line 6
    invoke-direct {p1, p0}, Lw0/o;-><init>(Lw0/p;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lw0/p;->f:Lw0/o;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final c()Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()Landroid/graphics/Bitmap;
    .locals 7

    .line 1
    const-string v0, "SurfaceViewImpl"

    .line 2
    .line 3
    iget-object v1, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 4
    .line 5
    if-eqz v1, :cond_2

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-interface {v1}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    iget-object v1, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 18
    .line 19
    invoke-virtual {v1}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {v1}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-virtual {v1}, Landroid/view/Surface;->isValid()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_0

    .line 32
    .line 33
    goto :goto_3

    .line 34
    :cond_0
    new-instance v1, Ljava/util/concurrent/Semaphore;

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    invoke-direct {v1, v2}, Ljava/util/concurrent/Semaphore;-><init>(I)V

    .line 38
    .line 39
    .line 40
    iget-object v2, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 41
    .line 42
    invoke-virtual {v2}, Landroid/view/View;->getWidth()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    iget-object v3, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 47
    .line 48
    invoke-virtual {v3}, Landroid/view/View;->getHeight()I

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    sget-object v4, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 53
    .line 54
    invoke-static {v2, v3, v4}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    new-instance v3, Landroid/os/HandlerThread;

    .line 59
    .line 60
    const-string v4, "pixelCopyRequest Thread"

    .line 61
    .line 62
    invoke-direct {v3, v4}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3}, Ljava/lang/Thread;->start()V

    .line 66
    .line 67
    .line 68
    new-instance v4, Landroid/os/Handler;

    .line 69
    .line 70
    invoke-virtual {v3}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    invoke-direct {v4, v5}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 78
    .line 79
    new-instance v5, Lw0/n;

    .line 80
    .line 81
    invoke-direct {v5, v1}, Lw0/n;-><init>(Ljava/util/concurrent/Semaphore;)V

    .line 82
    .line 83
    .line 84
    invoke-static {p0, v2, v5, v4}, Landroid/view/PixelCopy;->request(Landroid/view/SurfaceView;Landroid/graphics/Bitmap;Landroid/view/PixelCopy$OnPixelCopyFinishedListener;Landroid/os/Handler;)V

    .line 85
    .line 86
    .line 87
    :try_start_0
    sget-object p0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 88
    .line 89
    const/4 v4, 0x1

    .line 90
    const-wide/16 v5, 0x64

    .line 91
    .line 92
    invoke-virtual {v1, v4, v5, v6, p0}, Ljava/util/concurrent/Semaphore;->tryAcquire(IJLjava/util/concurrent/TimeUnit;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-nez p0, :cond_1

    .line 97
    .line 98
    const-string p0, "Timed out while trying to acquire screenshot."

    .line 99
    .line 100
    invoke-static {v0, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :catchall_0
    move-exception p0

    .line 105
    goto :goto_2

    .line 106
    :catch_0
    move-exception p0

    .line 107
    goto :goto_1

    .line 108
    :cond_1
    :goto_0
    invoke-virtual {v3}, Landroid/os/HandlerThread;->quitSafely()Z

    .line 109
    .line 110
    .line 111
    return-object v2

    .line 112
    :goto_1
    :try_start_1
    const-string v1, "Interrupted while trying to acquire screenshot."

    .line 113
    .line 114
    invoke-static {v0, v1, p0}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 115
    .line 116
    .line 117
    invoke-virtual {v3}, Landroid/os/HandlerThread;->quitSafely()Z

    .line 118
    .line 119
    .line 120
    return-object v2

    .line 121
    :goto_2
    invoke-virtual {v3}, Landroid/os/HandlerThread;->quitSafely()Z

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_2
    :goto_3
    const/4 p0, 0x0

    .line 126
    return-object p0
.end method

.method public final e()V
    .locals 0

    .line 1
    return-void
.end method

.method public final f()V
    .locals 0

    .line 1
    return-void
.end method

.method public final g(Lb0/x1;Lbb/i;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/core/app/a0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Landroid/util/Size;

    .line 6
    .line 7
    iget-object v2, p1, Lb0/x1;->b:Landroid/util/Size;

    .line 8
    .line 9
    invoke-static {v1, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-object v0, p1, Lb0/x1;->b:Landroid/util/Size;

    .line 19
    .line 20
    iput-object v0, p0, Landroidx/core/app/a0;->b:Ljava/lang/Object;

    .line 21
    .line 22
    iget-object v1, p0, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Landroid/widget/FrameLayout;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    new-instance v0, Landroid/view/SurfaceView;

    .line 30
    .line 31
    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-direct {v0, v2}, Landroid/view/SurfaceView;-><init>(Landroid/content/Context;)V

    .line 36
    .line 37
    .line 38
    iput-object v0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 39
    .line 40
    new-instance v2, Landroid/widget/FrameLayout$LayoutParams;

    .line 41
    .line 42
    iget-object v3, p0, Landroidx/core/app/a0;->b:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v3, Landroid/util/Size;

    .line 45
    .line 46
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    iget-object v4, p0, Landroidx/core/app/a0;->b:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v4, Landroid/util/Size;

    .line 53
    .line 54
    invoke-virtual {v4}, Landroid/util/Size;->getHeight()I

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    invoke-direct {v2, v3, v4}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0, v2}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 65
    .line 66
    .line 67
    iget-object v0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 68
    .line 69
    invoke-virtual {v1, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 73
    .line 74
    invoke-virtual {v0}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    iget-object v1, p0, Lw0/p;->f:Lw0/o;

    .line 79
    .line 80
    invoke-interface {v0, v1}, Landroid/view/SurfaceHolder;->addCallback(Landroid/view/SurfaceHolder$Callback;)V

    .line 81
    .line 82
    .line 83
    :goto_0
    iget-object v0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 84
    .line 85
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-virtual {v0}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    new-instance v1, Lm8/o;

    .line 94
    .line 95
    const/16 v2, 0x14

    .line 96
    .line 97
    invoke-direct {v1, p2, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 98
    .line 99
    .line 100
    iget-object v2, p1, Lb0/x1;->j:Ly4/h;

    .line 101
    .line 102
    invoke-virtual {v2, v0, v1}, Ly4/h;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 103
    .line 104
    .line 105
    iget-object v0, p0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 106
    .line 107
    new-instance v1, La8/y0;

    .line 108
    .line 109
    const/16 v2, 0x17

    .line 110
    .line 111
    invoke-direct {v1, p0, p1, p2, v2}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 115
    .line 116
    .line 117
    return-void
.end method

.method public final i()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 0

    .line 1
    sget-object p0, Lk0/j;->f:Lk0/j;

    .line 2
    .line 3
    return-object p0
.end method
