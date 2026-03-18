.class public final Lu/j;
.super Lh0/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lu/j;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ly4/h;Lh0/z;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lu/j;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lu/j;->b:Ljava/lang/Object;

    iput-object p2, p0, Lu/j;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(I)V
    .locals 5

    .line 1
    iget v0, p0, Lu/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object v0, p0, Lu/j;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/util/HashSet;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Lh0/m;

    .line 26
    .line 27
    :try_start_0
    iget-object v2, p0, Lu/j;->c:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Landroid/util/ArrayMap;

    .line 30
    .line 31
    invoke-virtual {v2, v1}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 36
    .line 37
    new-instance v3, La8/j0;

    .line 38
    .line 39
    const/4 v4, 0x5

    .line 40
    invoke-direct {v3, v1, p1, v4}, La8/j0;-><init>(Ljava/lang/Object;II)V

    .line 41
    .line 42
    .line 43
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :catch_0
    move-exception v1

    .line 48
    const-string v2, "Camera2CameraControlImp"

    .line 49
    .line 50
    const-string v3, "Executor rejected to invoke onCaptureCancelled."

    .line 51
    .line 52
    invoke-static {v2, v3, v1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(ILh0/s;)V
    .locals 5

    .line 1
    iget v0, p0, Lu/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lu/j;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Ly4/h;

    .line 9
    .line 10
    const/4 p2, 0x0

    .line 11
    invoke-virtual {p1, p2}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lu/j;->c:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Lh0/z;

    .line 17
    .line 18
    check-cast p1, Lh0/z;

    .line 19
    .line 20
    invoke-interface {p1, p0}, Lh0/z;->p(Lh0/m;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_0
    iget-object v0, p0, Lu/j;->b:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Ljava/util/HashSet;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Lh0/m;

    .line 43
    .line 44
    :try_start_0
    iget-object v2, p0, Lu/j;->c:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v2, Landroid/util/ArrayMap;

    .line 47
    .line 48
    invoke-virtual {v2, v1}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 53
    .line 54
    new-instance v3, Lb/p;

    .line 55
    .line 56
    const/4 v4, 0x5

    .line 57
    invoke-direct {v3, p1, v4, v1, p2}, Lb/p;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catch_0
    move-exception v1

    .line 65
    const-string v2, "Camera2CameraControlImp"

    .line 66
    .line 67
    const-string v3, "Executor rejected to invoke onCaptureCompleted."

    .line 68
    .line 69
    invoke-static {v2, v3, v1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_0
    return-void

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public c(ILpy/a;)V
    .locals 5

    .line 1
    iget v0, p0, Lu/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object v0, p0, Lu/j;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/util/HashSet;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Lh0/m;

    .line 26
    .line 27
    :try_start_0
    iget-object v2, p0, Lu/j;->c:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Landroid/util/ArrayMap;

    .line 30
    .line 31
    invoke-virtual {v2, v1}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 36
    .line 37
    new-instance v3, Lb/p;

    .line 38
    .line 39
    const/4 v4, 0x4

    .line 40
    invoke-direct {v3, p1, v4, v1, p2}, Lb/p;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :catch_0
    move-exception v1

    .line 48
    const-string v2, "Camera2CameraControlImp"

    .line 49
    .line 50
    const-string v3, "Executor rejected to invoke onCaptureFailed."

    .line 51
    .line 52
    invoke-static {v2, v3, v1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
