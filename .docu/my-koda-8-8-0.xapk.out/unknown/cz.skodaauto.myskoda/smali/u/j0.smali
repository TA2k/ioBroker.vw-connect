.class public final Lu/j0;
.super Landroid/hardware/camera2/CameraDevice$StateCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lu/j0;->a:I

    .line 2
    invoke-direct {p0}, Landroid/hardware/camera2/CameraDevice$StateCallback;-><init>()V

    .line 3
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 4
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 5
    instance-of v1, v0, Lu/k0;

    if-nez v1, :cond_0

    .line 6
    iget-object v1, p0, Lu/j0;->b:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    return-void
.end method

.method public constructor <init>(Lu/x0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lu/j0;->a:I

    .line 1
    iput-object p1, p0, Lu/j0;->b:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/hardware/camera2/CameraDevice$StateCallback;-><init>()V

    return-void
.end method

.method private final c(Landroid/hardware/camera2/CameraDevice;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lu/x0;

    .line 4
    .line 5
    iget-object v0, v0, Lu/x0;->b:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    iget-object v1, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lu/x0;

    .line 11
    .line 12
    invoke-virtual {v1}, Lu/x0;->h()Ljava/util/ArrayList;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iget-object v2, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v2, Lu/x0;

    .line 19
    .line 20
    iget-object v2, v2, Lu/x0;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v2, Ljava/util/LinkedHashSet;

    .line 23
    .line 24
    invoke-interface {v2}, Ljava/util/Set;->clear()V

    .line 25
    .line 26
    .line 27
    iget-object v2, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Lu/x0;

    .line 30
    .line 31
    iget-object v2, v2, Lu/x0;->c:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v2, Ljava/util/LinkedHashSet;

    .line 34
    .line 35
    invoke-interface {v2}, Ljava/util/Set;->clear()V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lu/x0;

    .line 41
    .line 42
    iget-object p0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Ljava/util/LinkedHashSet;

    .line 45
    .line 46
    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 47
    .line 48
    .line 49
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 50
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Lu/g1;

    .line 65
    .line 66
    iget-object v1, v0, Lu/g1;->a:Ljava/lang/Object;

    .line 67
    .line 68
    monitor-enter v1

    .line 69
    :try_start_1
    iget-object v2, v0, Lu/g1;->j:Ljava/util/List;

    .line 70
    .line 71
    if-eqz v2, :cond_1

    .line 72
    .line 73
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_0

    .line 82
    .line 83
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    check-cast v3, Lh0/t0;

    .line 88
    .line 89
    invoke-virtual {v3}, Lh0/t0;->b()V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_0
    const/4 v2, 0x0

    .line 94
    iput-object v2, v0, Lu/g1;->j:Ljava/util/List;

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :catchall_0
    move-exception p0

    .line 98
    goto :goto_3

    .line 99
    :cond_1
    :goto_2
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 100
    iget-object v0, v0, Lu/g1;->t:Lb6/f;

    .line 101
    .line 102
    invoke-virtual {v0}, Lb6/f;->x()V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :goto_3
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 107
    throw p0

    .line 108
    :cond_2
    return-void

    .line 109
    :catchall_1
    move-exception p0

    .line 110
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 111
    throw p0
.end method

.method public b()V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lu/x0;

    .line 9
    .line 10
    iget-object v1, v1, Lu/x0;->b:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v1

    .line 13
    :try_start_0
    iget-object v2, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Lu/x0;

    .line 16
    .line 17
    iget-object v2, v2, Lu/x0;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Ljava/util/LinkedHashSet;

    .line 20
    .line 21
    invoke-virtual {v0, v2}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 22
    .line 23
    .line 24
    iget-object v2, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v2, Lu/x0;

    .line 27
    .line 28
    iget-object v2, v2, Lu/x0;->c:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v2, Ljava/util/LinkedHashSet;

    .line 31
    .line 32
    invoke-virtual {v0, v2}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 33
    .line 34
    .line 35
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    iget-object p0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lu/x0;

    .line 39
    .line 40
    iget-object p0, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lj0/h;

    .line 43
    .line 44
    new-instance v1, Lm8/o;

    .line 45
    .line 46
    const/16 v2, 0x10

    .line 47
    .line 48
    invoke-direct {v1, v0, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    throw p0
.end method

.method public final onClosed(Landroid/hardware/camera2/CameraDevice;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/j0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lu/j0;->b()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lu/j0;->a()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :pswitch_0
    iget-object p0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Landroid/hardware/camera2/CameraDevice$StateCallback;->onClosed(Landroid/hardware/camera2/CameraDevice;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onDisconnected(Landroid/hardware/camera2/CameraDevice;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/j0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lu/j0;->b()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lu/j0;->a()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :pswitch_0
    iget-object p0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Landroid/hardware/camera2/CameraDevice$StateCallback;->onDisconnected(Landroid/hardware/camera2/CameraDevice;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onError(Landroid/hardware/camera2/CameraDevice;I)V
    .locals 3

    .line 1
    iget v0, p0, Lu/j0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lu/j0;->b()V

    .line 7
    .line 8
    .line 9
    new-instance p1, Ljava/util/LinkedHashSet;

    .line 10
    .line 11
    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lu/x0;

    .line 17
    .line 18
    iget-object v0, v0, Lu/x0;->b:Ljava/lang/Object;

    .line 19
    .line 20
    monitor-enter v0

    .line 21
    :try_start_0
    iget-object v1, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lu/x0;

    .line 24
    .line 25
    iget-object v1, v1, Lu/x0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v1, Ljava/util/LinkedHashSet;

    .line 28
    .line 29
    invoke-virtual {p1, v1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lu/x0;

    .line 35
    .line 36
    iget-object v1, v1, Lu/x0;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Ljava/util/LinkedHashSet;

    .line 39
    .line 40
    invoke-virtual {p1, v1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 41
    .line 42
    .line 43
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    iget-object v0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Lu/x0;

    .line 47
    .line 48
    iget-object v0, v0, Lu/x0;->a:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v0, Lj0/h;

    .line 51
    .line 52
    new-instance v1, La8/j0;

    .line 53
    .line 54
    const/4 v2, 0x6

    .line 55
    invoke-direct {v1, p1, p2, v2}, La8/j0;-><init>(Ljava/lang/Object;II)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0}, Lu/j0;->a()V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :catchall_0
    move-exception p0

    .line 66
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 67
    throw p0

    .line 68
    :pswitch_0
    iget-object p0, p0, Lu/j0;->b:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_0

    .line 81
    .line 82
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 87
    .line 88
    invoke-virtual {v0, p1, p2}, Landroid/hardware/camera2/CameraDevice$StateCallback;->onError(Landroid/hardware/camera2/CameraDevice;I)V

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_0
    return-void

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onOpened(Landroid/hardware/camera2/CameraDevice;)V
    .locals 1

    .line 1
    iget v0, p0, Lu/j0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lu/j0;->b:Ljava/lang/Object;

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
    check-cast v0, Landroid/hardware/camera2/CameraDevice$StateCallback;

    .line 26
    .line 27
    invoke-virtual {v0, p1}, Landroid/hardware/camera2/CameraDevice$StateCallback;->onOpened(Landroid/hardware/camera2/CameraDevice;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
