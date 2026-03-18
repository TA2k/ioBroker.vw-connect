.class public final synthetic Lbb/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/i;
.implements Laq/b;
.implements Ly4/i;
.implements Laq/g;
.implements Lj8/l;
.implements Lyz0/d;
.implements Lk0/a;
.implements Lb0/w1;
.implements Lzn/b;
.implements Lyn/f;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lbb/i;->d:I

    iput-object p1, p0, Lbb/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lbb/i;->f:Ljava/lang/Object;

    iput-object p3, p0, Lbb/i;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Runnable;Lbb/x;Ljava/lang/Runnable;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lbb/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbb/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lbb/i;->g:Ljava/lang/Object;

    iput-object p3, p0, Lbb/i;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lpx0/g;Lvy0/c0;Lay0/n;)V
    .locals 1

    .line 3
    const/4 v0, 0x5

    iput v0, p0, Lbb/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbb/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lbb/i;->f:Ljava/lang/Object;

    check-cast p3, Lrx0/i;

    iput-object p3, p0, Lbb/i;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt1/j0;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lw0/c;

    .line 8
    .line 9
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lh0/b0;

    .line 12
    .line 13
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lw0/i;

    .line 16
    .line 17
    iget-object v0, v0, Lw0/i;->j:Ljava/util/concurrent/atomic/AtomicReference;

    .line 18
    .line 19
    :cond_0
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    sget-object v0, Lw0/h;->d:Lw0/h;

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Lw0/c;->b(Lw0/h;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    if-eq v3, v1, :cond_0

    .line 37
    .line 38
    :goto_0
    iget-object v0, v1, Lw0/c;->e:Lk0/d;

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    invoke-interface {v0, v3}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 44
    .line 45
    .line 46
    iput-object v2, v1, Lw0/c;->e:Lk0/d;

    .line 47
    .line 48
    :cond_2
    invoke-interface {p0}, Lh0/b0;->c()Lh0/m1;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-interface {p0, v1}, Lh0/m1;->f(Lh0/l1;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 21

    move-object/from16 v0, p0

    const-string v1, "openCaptureSession() should not be possible in state: "

    const-string v2, "openCaptureSession() not execute in state: "

    iget-object v3, v0, Lbb/i;->e:Ljava/lang/Object;

    check-cast v3, Lu/p0;

    iget-object v4, v0, Lbb/i;->f:Ljava/lang/Object;

    check-cast v4, Lh0/z1;

    iget-object v0, v0, Lbb/i;->g:Ljava/lang/Object;

    check-cast v0, Landroid/hardware/camera2/CameraDevice;

    move-object/from16 v5, p1

    check-cast v5, Ljava/util/List;

    .line 1
    iget-object v6, v3, Lu/p0;->a:Ljava/lang/Object;

    monitor-enter v6

    .line 2
    :try_start_0
    iget v7, v3, Lu/p0;->j:I

    invoke-static {v7}, Lu/w;->o(I)I

    move-result v7

    const/4 v8, 0x1

    if-eqz v7, :cond_e

    const/4 v9, 0x7

    if-eq v7, v9, :cond_e

    const/4 v10, 0x2

    if-eq v7, v10, :cond_e

    const/4 v1, 0x3

    if-eq v7, v1, :cond_0

    .line 3
    new-instance v0, Ljava/util/concurrent/CancellationException;

    iget v1, v3, Lu/p0;->j:I

    invoke-static {v1}, Lu/w;->q(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 4
    new-instance v1, Lk0/j;

    invoke-direct {v1, v0, v8}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 5
    monitor-exit v6

    return-object v1

    :catchall_0
    move-exception v0

    move-object/from16 v20, v6

    goto/16 :goto_7

    .line 6
    :cond_0
    iget-object v1, v3, Lu/p0;->g:Ljava/util/HashMap;

    invoke-virtual {v1}, Ljava/util/HashMap;->clear()V

    const/4 v1, 0x0

    move v2, v1

    .line 7
    :goto_0
    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v7

    if-ge v2, v7, :cond_1

    .line 8
    iget-object v7, v3, Lu/p0;->g:Ljava/util/HashMap;

    iget-object v11, v3, Lu/p0;->h:Ljava/util/List;

    invoke-interface {v11, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Lh0/t0;

    .line 9
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Landroid/view/Surface;

    .line 10
    invoke-virtual {v7, v11, v12}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 11
    :cond_1
    invoke-virtual {v3, v9}, Lu/p0;->p(I)V

    .line 12
    const-string v2, "CaptureSession"

    const-string v5, "Opening capture session."

    invoke-static {v2, v5}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    iget-object v2, v3, Lu/p0;->c:Lu/o0;

    new-instance v5, Lu/o0;

    .line 14
    iget-object v7, v4, Lh0/z1;->d:Ljava/util/List;

    .line 15
    invoke-direct {v5, v7, v8}, Lu/o0;-><init>(Ljava/util/List;I)V

    new-array v7, v10, [Lu/d1;

    aput-object v2, v7, v1

    aput-object v5, v7, v8

    .line 16
    new-instance v2, Lu/o0;

    invoke-static {v7}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    invoke-direct {v2, v5, v10}, Lu/o0;-><init>(Ljava/util/List;I)V

    .line 17
    new-instance v5, Lt/a;

    .line 18
    iget-object v7, v4, Lh0/z1;->g:Lh0/o0;

    .line 19
    iget-object v9, v7, Lh0/o0;->b:Lh0/n1;

    .line 20
    invoke-direct {v5, v9, v1}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 21
    new-instance v1, Ljava/util/HashSet;

    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 22
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 23
    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 24
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    .line 25
    iget-object v10, v7, Lh0/o0;->a:Ljava/util/ArrayList;

    invoke-interface {v1, v10}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 26
    iget-object v10, v7, Lh0/o0;->b:Lh0/n1;

    invoke-static {v10}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    move-result-object v10

    .line 27
    iget v14, v7, Lh0/o0;->c:I

    .line 28
    iget-object v11, v7, Lh0/o0;->d:Ljava/util/List;

    .line 29
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 30
    iget-boolean v11, v7, Lh0/o0;->e:Z

    .line 31
    iget-object v7, v7, Lh0/o0;->f:Lh0/j2;

    .line 32
    new-instance v12, Landroid/util/ArrayMap;

    invoke-direct {v12}, Landroid/util/ArrayMap;-><init>()V

    .line 33
    iget-object v13, v7, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 34
    invoke-virtual {v13}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    move-result-object v13

    .line 35
    invoke-interface {v13}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v13

    :goto_1
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_2

    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Ljava/lang/String;

    .line 36
    iget-object v8, v7, Lh0/j2;->a:Landroid/util/ArrayMap;

    invoke-virtual {v8, v15}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    .line 37
    invoke-virtual {v12, v15, v8}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v8, 0x1

    goto :goto_1

    .line 38
    :cond_2
    new-instance v7, Lh0/k1;

    .line 39
    invoke-direct {v7, v12}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 40
    new-instance v8, Ljava/util/HashMap;

    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 41
    iget-boolean v12, v3, Lu/p0;->s:Z

    const/16 v13, 0x23

    if-eqz v12, :cond_3

    sget v12, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v12, v13, :cond_3

    .line 42
    iget-object v8, v4, Lh0/z1;->a:Ljava/util/ArrayList;

    .line 43
    invoke-static {v8}, Lu/p0;->h(Ljava/util/ArrayList;)Ljava/util/HashMap;

    move-result-object v8

    .line 44
    iget-object v12, v3, Lu/p0;->g:Ljava/util/HashMap;

    .line 45
    invoke-static {v8, v12}, Lu/p0;->d(Ljava/util/HashMap;Ljava/util/HashMap;)Ljava/util/HashMap;

    move-result-object v8

    .line 46
    :cond_3
    new-instance v12, Ljava/util/ArrayList;

    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 47
    iget-object v5, v5, La0/j;->e:Ljava/lang/Object;

    check-cast v5, Lh0/q0;

    .line 48
    sget-object v15, Lt/a;->k:Lh0/g;

    const/4 v13, 0x0

    invoke-interface {v5, v15, v13}, Lh0/q0;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    .line 49
    iget-object v15, v4, Lh0/z1;->a:Ljava/util/ArrayList;

    .line 50
    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v15

    :goto_2
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    move-result v16

    if-eqz v16, :cond_8

    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v13, v16

    check-cast v13, Lh0/i;

    move-object/from16 v16, v10

    .line 51
    iget-boolean v10, v3, Lu/p0;->s:Z

    if-eqz v10, :cond_4

    sget v10, Landroid/os/Build$VERSION;->SDK_INT:I

    move/from16 v18, v11

    const/16 v11, 0x23

    if-lt v10, v11, :cond_5

    .line 52
    invoke-interface {v8, v13}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Lw/h;

    goto :goto_3

    :cond_4
    move/from16 v18, v11

    const/16 v11, 0x23

    :cond_5
    const/4 v10, 0x0

    :goto_3
    if-nez v10, :cond_6

    .line 53
    iget-object v10, v3, Lu/p0;->g:Ljava/util/HashMap;

    invoke-virtual {v3, v13, v10, v5}, Lu/p0;->f(Lh0/i;Ljava/util/HashMap;Ljava/lang/String;)Lw/h;

    move-result-object v10

    .line 54
    iget-object v11, v3, Lu/p0;->m:Ljava/util/HashMap;

    move-object/from16 v19, v5

    .line 55
    iget-object v5, v13, Lh0/i;->a:Lh0/t0;

    .line 56
    invoke-virtual {v11, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7

    .line 57
    iget-object v5, v3, Lu/p0;->m:Ljava/util/HashMap;

    .line 58
    iget-object v11, v13, Lh0/i;->a:Lh0/t0;

    .line 59
    invoke-virtual {v5, v11}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Long;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object/from16 v20, v6

    :try_start_1
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    move-result-wide v5

    .line 60
    iget-object v11, v10, Lw/h;->a:Lw/j;

    invoke-virtual {v11, v5, v6}, Lw/j;->e(J)V

    goto :goto_4

    :catchall_1
    move-exception v0

    goto/16 :goto_7

    :cond_6
    move-object/from16 v19, v5

    :cond_7
    move-object/from16 v20, v6

    .line 61
    :goto_4
    invoke-virtual {v12, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v10, v16

    move/from16 v11, v18

    move-object/from16 v5, v19

    move-object/from16 v6, v20

    const/4 v13, 0x0

    goto :goto_2

    :cond_8
    move-object/from16 v20, v6

    move-object/from16 v16, v10

    move/from16 v18, v11

    .line 62
    invoke-static {v12}, Lu/p0;->g(Ljava/util/ArrayList;)Ljava/util/ArrayList;

    move-result-object v5

    .line 63
    iget-object v6, v3, Lu/p0;->d:Lu/g1;

    .line 64
    iget v8, v4, Lh0/z1;->h:I

    .line 65
    iput-object v2, v6, Lu/g1;->e:Lu/o0;

    .line 66
    new-instance v2, Lw/m;

    .line 67
    iget-object v10, v6, Lu/g1;->c:Lj0/h;

    .line 68
    new-instance v11, Lu/h0;

    const/4 v12, 0x1

    invoke-direct {v11, v6, v12}, Lu/h0;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v2, v8, v5, v10, v11}, Lw/m;-><init>(ILjava/util/ArrayList;Lj0/h;Lu/h0;)V

    .line 69
    iget-object v5, v4, Lh0/z1;->g:Lh0/o0;

    .line 70
    iget v5, v5, Lh0/o0;->c:I

    const/4 v6, 0x5

    if-ne v5, v6, :cond_b

    .line 71
    iget-object v4, v4, Lh0/z1;->i:Landroid/hardware/camera2/params/InputConfiguration;

    if-eqz v4, :cond_b

    if-nez v4, :cond_9

    const/4 v13, 0x0

    goto :goto_5

    .line 72
    :cond_9
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v6, 0x1f

    if-lt v5, v6, :cond_a

    .line 73
    new-instance v13, Lw/g;

    new-instance v5, Lw/f;

    .line 74
    invoke-direct {v5, v4}, Lw/e;-><init>(Ljava/lang/Object;)V

    .line 75
    invoke-direct {v13, v5}, Lw/g;-><init>(Lw/e;)V

    goto :goto_5

    .line 76
    :cond_a
    new-instance v13, Lw/g;

    new-instance v5, Lw/e;

    invoke-direct {v5, v4}, Lw/e;-><init>(Ljava/lang/Object;)V

    invoke-direct {v13, v5}, Lw/g;-><init>(Lw/e;)V

    .line 77
    :goto_5
    iget-object v4, v2, Lw/m;->a:Lw/l;

    .line 78
    iget-object v4, v4, Lw/l;->a:Landroid/hardware/camera2/params/SessionConfiguration;

    .line 79
    iget-object v5, v13, Lw/g;->a:Lw/e;

    .line 80
    iget-object v5, v5, Lw/e;->a:Landroid/hardware/camera2/params/InputConfiguration;

    .line 81
    invoke-virtual {v4, v5}, Landroid/hardware/camera2/params/SessionConfiguration;->setInputConfiguration(Landroid/hardware/camera2/params/InputConfiguration;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 82
    :cond_b
    :try_start_2
    new-instance v11, Lh0/o0;

    new-instance v12, Ljava/util/ArrayList;

    invoke-direct {v12, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 83
    invoke-static/range {v16 .. v16}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    move-result-object v13

    new-instance v15, Ljava/util/ArrayList;

    invoke-direct {v15, v9}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 84
    sget-object v1, Lh0/j2;->b:Lh0/j2;

    .line 85
    new-instance v1, Landroid/util/ArrayMap;

    invoke-direct {v1}, Landroid/util/ArrayMap;-><init>()V

    .line 86
    iget-object v4, v7, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 87
    invoke-virtual {v4}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    move-result-object v4

    .line 88
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_6
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_c

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    .line 89
    iget-object v6, v7, Lh0/j2;->a:Landroid/util/ArrayMap;

    invoke-virtual {v6, v5}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    .line 90
    invoke-virtual {v1, v5, v6}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_6

    .line 91
    :cond_c
    new-instance v4, Lh0/j2;

    invoke-direct {v4, v1}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    move/from16 v16, v18

    const/16 v18, 0x0

    move-object/from16 v17, v4

    .line 92
    invoke-direct/range {v11 .. v18}, Lh0/o0;-><init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V

    .line 93
    iget-object v1, v3, Lu/p0;->r:Lk1/c0;

    .line 94
    invoke-static {v11, v0, v1}, Llp/w0;->e(Lh0/o0;Landroid/hardware/camera2/CameraDevice;Lk1/c0;)Landroid/hardware/camera2/CaptureRequest;

    move-result-object v1

    if-eqz v1, :cond_d

    .line 95
    iget-object v4, v2, Lw/m;->a:Lw/l;

    .line 96
    iget-object v4, v4, Lw/l;->a:Landroid/hardware/camera2/params/SessionConfiguration;

    .line 97
    invoke-virtual {v4, v1}, Landroid/hardware/camera2/params/SessionConfiguration;->setSessionParameters(Landroid/hardware/camera2/CaptureRequest;)V
    :try_end_2
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 98
    :cond_d
    :try_start_3
    iget-object v1, v3, Lu/p0;->d:Lu/g1;

    iget-object v3, v3, Lu/p0;->h:Ljava/util/List;

    invoke-virtual {v1, v0, v2, v3}, Lu/g1;->m(Landroid/hardware/camera2/CameraDevice;Lw/m;Ljava/util/List;)Lcom/google/common/util/concurrent/ListenableFuture;

    move-result-object v0

    monitor-exit v20

    return-object v0

    :catch_0
    move-exception v0

    .line 99
    new-instance v1, Lk0/j;

    const/4 v12, 0x1

    invoke-direct {v1, v0, v12}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 100
    monitor-exit v20

    return-object v1

    :cond_e
    move-object/from16 v20, v6

    .line 101
    new-instance v0, Ljava/lang/IllegalStateException;

    iget v2, v3, Lu/p0;->j:I

    invoke-static {v2}, Lu/w;->q(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 102
    new-instance v1, Lk0/j;

    const/4 v12, 0x1

    invoke-direct {v1, v0, v12}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 103
    monitor-exit v20

    return-object v1

    .line 104
    :goto_7
    monitor-exit v20
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    throw v0
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    move-object/from16 v0, p0

    iget v1, v0, Lbb/i;->d:I

    const-string v3, "bytes"

    const-string v4, "PRAGMA page_size"

    const-string v5, "PRAGMA page_count"

    const/4 v6, 0x6

    const/4 v7, 0x5

    const/4 v8, 0x4

    const/4 v9, 0x3

    sget-object v10, Lun/d;->g:Lun/d;

    const/4 v11, 0x2

    const/4 v12, 0x1

    iget-object v13, v0, Lbb/i;->g:Ljava/lang/Object;

    iget-object v14, v0, Lbb/i;->f:Ljava/lang/Object;

    iget-object v0, v0, Lbb/i;->e:Ljava/lang/Object;

    const/4 v15, 0x0

    packed-switch v1, :pswitch_data_0

    check-cast v0, Lyn/h;

    check-cast v14, Ljava/util/HashMap;

    check-cast v13, Lun/a;

    iget-object v1, v13, Lun/a;->f:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    move-object/from16 v2, p1

    check-cast v2, Landroid/database/Cursor;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    :goto_0
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    move-result v3

    if-eqz v3, :cond_8

    .line 106
    invoke-interface {v2, v15}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v3

    .line 107
    invoke-interface {v2, v12}, Landroid/database/Cursor;->getInt(I)I

    move-result v15

    .line 108
    sget-object v16, Lun/d;->e:Lun/d;

    if-nez v15, :cond_0

    :goto_1
    move-object/from16 v6, v16

    goto :goto_2

    :cond_0
    if-ne v15, v12, :cond_1

    .line 109
    sget-object v16, Lun/d;->f:Lun/d;

    goto :goto_1

    :cond_1
    if-ne v15, v11, :cond_2

    move-object v6, v10

    goto :goto_2

    :cond_2
    if-ne v15, v9, :cond_3

    .line 110
    sget-object v16, Lun/d;->h:Lun/d;

    goto :goto_1

    :cond_3
    if-ne v15, v8, :cond_4

    .line 111
    sget-object v16, Lun/d;->i:Lun/d;

    goto :goto_1

    :cond_4
    if-ne v15, v7, :cond_5

    .line 112
    sget-object v16, Lun/d;->j:Lun/d;

    goto :goto_1

    :cond_5
    if-ne v15, v6, :cond_6

    .line 113
    sget-object v16, Lun/d;->k:Lun/d;

    goto :goto_1

    .line 114
    :cond_6
    const-string v6, "%n is not valid. No matched LogEventDropped-Reason found. Treated it as REASON_UNKNOWN"

    .line 115
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    .line 116
    const-string v7, "SQLiteEventStore"

    invoke-static {v15, v7, v6}, Llp/wb;->b(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_1

    .line 117
    :goto_2
    invoke-interface {v2, v11}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v8

    .line 118
    invoke-virtual {v14, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v16

    if-nez v16, :cond_7

    .line 119
    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v14, v3, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    :cond_7
    invoke-virtual {v14, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    .line 121
    new-instance v7, Lun/e;

    invoke-direct {v7, v8, v9, v6}, Lun/e;-><init>(JLun/d;)V

    .line 122
    invoke-interface {v3, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    const/4 v6, 0x6

    const/4 v7, 0x5

    const/4 v8, 0x4

    const/4 v9, 0x3

    const/4 v15, 0x0

    goto :goto_0

    .line 123
    :cond_8
    invoke-virtual {v14}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    .line 124
    sget v6, Lun/f;->c:I

    .line 125
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 126
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    .line 127
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    .line 128
    new-instance v7, Lun/f;

    invoke-static {v3}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v3

    invoke-direct {v7, v6, v3}, Lun/f;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 129
    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    .line 130
    :cond_9
    iget-object v2, v0, Lyn/h;->e:Lao/a;

    invoke-interface {v2}, Lao/a;->a()J

    move-result-wide v2

    .line 131
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v6

    .line 132
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 133
    :try_start_0
    const-string v7, "SELECT last_metrics_upload_ms FROM global_log_event_state LIMIT 1"

    const/4 v8, 0x0

    new-array v9, v8, [Ljava/lang/String;

    .line 134
    invoke-virtual {v6, v7, v9}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 135
    :try_start_1
    invoke-interface {v7}, Landroid/database/Cursor;->moveToNext()Z

    .line 136
    invoke-interface {v7, v8}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v8

    .line 137
    new-instance v10, Lun/h;

    invoke-direct {v10, v8, v9, v2, v3}, Lun/h;-><init>(JJ)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 138
    :try_start_2
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 139
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 140
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 141
    iput-object v10, v13, Lun/a;->e:Ljava/lang/Object;

    .line 142
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v2

    invoke-virtual {v2, v5}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    move-result-object v2

    invoke-virtual {v2}, Landroid/database/sqlite/SQLiteStatement;->simpleQueryForLong()J

    move-result-wide v2

    .line 143
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v5

    invoke-virtual {v5, v4}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    move-result-object v4

    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteStatement;->simpleQueryForLong()J

    move-result-wide v4

    mul-long/2addr v4, v2

    .line 144
    sget-object v2, Lyn/a;->f:Lyn/a;

    .line 145
    iget-wide v2, v2, Lyn/a;->a:J

    .line 146
    new-instance v6, Lun/g;

    invoke-direct {v6, v4, v5, v2, v3}, Lun/g;-><init>(JJ)V

    .line 147
    new-instance v2, Lun/c;

    invoke-direct {v2, v6}, Lun/c;-><init>(Lun/g;)V

    .line 148
    iput-object v2, v13, Lun/a;->g:Ljava/lang/Object;

    .line 149
    iget-object v0, v0, Lyn/h;->h:Lkx0/a;

    .line 150
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 151
    iput-object v0, v13, Lun/a;->h:Ljava/lang/Object;

    .line 152
    new-instance v0, Lun/b;

    iget-object v2, v13, Lun/a;->e:Ljava/lang/Object;

    check-cast v2, Lun/h;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iget-object v3, v13, Lun/a;->g:Ljava/lang/Object;

    check-cast v3, Lun/c;

    iget-object v4, v13, Lun/a;->h:Ljava/lang/Object;

    check-cast v4, Ljava/lang/String;

    invoke-direct {v0, v2, v1, v3, v4}, Lun/b;-><init>(Lun/h;Ljava/util/List;Lun/c;Ljava/lang/String;)V

    return-object v0

    :catchall_0
    move-exception v0

    goto :goto_4

    :catchall_1
    move-exception v0

    .line 153
    :try_start_3
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 154
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 155
    :goto_4
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 156
    throw v0

    .line 157
    :pswitch_0
    check-cast v0, Lyn/h;

    check-cast v14, Ljava/util/ArrayList;

    check-cast v13, Lrn/j;

    move-object/from16 v1, p1

    check-cast v1, Landroid/database/Cursor;

    .line 158
    :goto_5
    invoke-interface {v1}, Landroid/database/Cursor;->moveToNext()Z

    move-result v4

    if-eqz v4, :cond_16

    const/4 v8, 0x0

    .line 159
    invoke-interface {v1, v8}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    const/4 v6, 0x7

    .line 160
    invoke-interface {v1, v6}, Landroid/database/Cursor;->getInt(I)I

    move-result v6

    if-eqz v6, :cond_a

    move v6, v12

    goto :goto_6

    :cond_a
    const/4 v6, 0x0

    .line 161
    :goto_6
    new-instance v8, Lg1/q;

    .line 162
    invoke-direct {v8}, Lg1/q;-><init>()V

    .line 163
    new-instance v7, Ljava/util/HashMap;

    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 164
    iput-object v7, v8, Lg1/q;->g:Ljava/lang/Object;

    .line 165
    invoke-interface {v1, v12}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v7

    if-eqz v7, :cond_15

    .line 166
    iput-object v7, v8, Lg1/q;->b:Ljava/lang/Object;

    .line 167
    invoke-interface {v1, v11}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v9

    .line 168
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v7

    iput-object v7, v8, Lg1/q;->e:Ljava/lang/Object;

    const/4 v15, 0x3

    .line 169
    invoke-interface {v1, v15}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v9

    .line 170
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v7

    iput-object v7, v8, Lg1/q;->f:Ljava/lang/Object;

    if-eqz v6, :cond_c

    .line 171
    new-instance v6, Lrn/m;

    const/4 v7, 0x4

    .line 172
    invoke-interface {v1, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v9

    if-nez v9, :cond_b

    .line 173
    sget-object v9, Lyn/h;->i:Lon/c;

    :goto_7
    const/4 v10, 0x5

    goto :goto_8

    .line 174
    :cond_b
    new-instance v10, Lon/c;

    invoke-direct {v10, v9}, Lon/c;-><init>(Ljava/lang/String;)V

    move-object v9, v10

    goto :goto_7

    .line 175
    :goto_8
    invoke-interface {v1, v10}, Landroid/database/Cursor;->getBlob(I)[B

    move-result-object v7

    invoke-direct {v6, v9, v7}, Lrn/m;-><init>(Lon/c;[B)V

    .line 176
    iput-object v6, v8, Lg1/q;->d:Ljava/lang/Object;

    move-object/from16 v22, v0

    const/16 v21, 0x0

    :goto_9
    const/4 v0, 0x6

    goto/16 :goto_d

    :cond_c
    const/4 v10, 0x5

    .line 177
    new-instance v6, Lrn/m;

    const/4 v7, 0x4

    .line 178
    invoke-interface {v1, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v9

    if-nez v9, :cond_d

    .line 179
    sget-object v9, Lyn/h;->i:Lon/c;

    goto :goto_a

    .line 180
    :cond_d
    new-instance v7, Lon/c;

    invoke-direct {v7, v9}, Lon/c;-><init>(Ljava/lang/String;)V

    move-object v9, v7

    .line 181
    :goto_a
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v17

    filled-new-array {v3}, [Ljava/lang/String;

    move-result-object v19

    .line 182
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v7

    filled-new-array {v7}, [Ljava/lang/String;

    move-result-object v21

    const/16 v23, 0x0

    const-string v24, "sequence_num"

    .line 183
    const-string v18, "event_payloads"

    const-string v20, "event_id = ?"

    const/16 v22, 0x0

    invoke-virtual/range {v17 .. v24}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v7

    .line 184
    :try_start_4
    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    const/4 v11, 0x0

    .line 185
    :goto_b
    invoke-interface {v7}, Landroid/database/Cursor;->moveToNext()Z

    move-result v19

    if-eqz v19, :cond_e

    const/4 v12, 0x0

    .line 186
    invoke-interface {v7, v12}, Landroid/database/Cursor;->getBlob(I)[B

    move-result-object v15

    .line 187
    invoke-virtual {v10, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 188
    array-length v12, v15

    add-int/2addr v11, v12

    const/4 v12, 0x1

    const/4 v15, 0x3

    goto :goto_b

    .line 189
    :cond_e
    new-array v11, v11, [B

    const/4 v12, 0x0

    const/4 v15, 0x0

    const/16 v21, 0x0

    .line 190
    :goto_c
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    move-result v2

    if-ge v12, v2, :cond_f

    .line 191
    invoke-virtual {v10, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, [B

    move-object/from16 v22, v0

    .line 192
    array-length v0, v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    move-object/from16 p1, v7

    const/4 v7, 0x0

    :try_start_5
    invoke-static {v2, v7, v11, v15, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 193
    array-length v0, v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    add-int/2addr v15, v0

    add-int/lit8 v12, v12, 0x1

    move-object/from16 v7, p1

    move-object/from16 v0, v22

    goto :goto_c

    :catchall_2
    move-exception v0

    goto :goto_e

    :cond_f
    move-object/from16 v22, v0

    move-object/from16 p1, v7

    .line 194
    invoke-interface/range {p1 .. p1}, Landroid/database/Cursor;->close()V

    .line 195
    invoke-direct {v6, v9, v11}, Lrn/m;-><init>(Lon/c;[B)V

    .line 196
    iput-object v6, v8, Lg1/q;->d:Ljava/lang/Object;

    goto :goto_9

    .line 197
    :goto_d
    invoke-interface {v1, v0}, Landroid/database/Cursor;->isNull(I)Z

    move-result v2

    if-nez v2, :cond_10

    .line 198
    invoke-interface {v1, v0}, Landroid/database/Cursor;->getInt(I)I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    .line 199
    iput-object v2, v8, Lg1/q;->c:Ljava/lang/Object;

    :cond_10
    const/16 v2, 0x8

    .line 200
    invoke-interface {v1, v2}, Landroid/database/Cursor;->isNull(I)Z

    move-result v6

    if-nez v6, :cond_11

    .line 201
    invoke-interface {v1, v2}, Landroid/database/Cursor;->getInt(I)I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    .line 202
    iput-object v2, v8, Lg1/q;->h:Ljava/lang/Object;

    :cond_11
    const/16 v2, 0x9

    .line 203
    invoke-interface {v1, v2}, Landroid/database/Cursor;->isNull(I)Z

    move-result v6

    if-nez v6, :cond_12

    .line 204
    invoke-interface {v1, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v2

    .line 205
    iput-object v2, v8, Lg1/q;->i:Ljava/lang/Object;

    :cond_12
    const/16 v2, 0xa

    .line 206
    invoke-interface {v1, v2}, Landroid/database/Cursor;->isNull(I)Z

    move-result v6

    if-nez v6, :cond_13

    .line 207
    invoke-interface {v1, v2}, Landroid/database/Cursor;->getBlob(I)[B

    move-result-object v2

    .line 208
    iput-object v2, v8, Lg1/q;->j:Ljava/lang/Object;

    :cond_13
    const/16 v2, 0xb

    .line 209
    invoke-interface {v1, v2}, Landroid/database/Cursor;->isNull(I)Z

    move-result v6

    if-nez v6, :cond_14

    .line 210
    invoke-interface {v1, v2}, Landroid/database/Cursor;->getBlob(I)[B

    move-result-object v2

    .line 211
    iput-object v2, v8, Lg1/q;->k:Ljava/lang/Object;

    .line 212
    :cond_14
    invoke-virtual {v8}, Lg1/q;->d()Lrn/h;

    move-result-object v2

    .line 213
    new-instance v6, Lyn/b;

    invoke-direct {v6, v4, v5, v13, v2}, Lyn/b;-><init>(JLrn/j;Lrn/h;)V

    .line 214
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v0, v22

    const/4 v11, 0x2

    const/4 v12, 0x1

    goto/16 :goto_5

    :catchall_3
    move-exception v0

    move-object/from16 p1, v7

    .line 215
    :goto_e
    invoke-interface/range {p1 .. p1}, Landroid/database/Cursor;->close()V

    .line 216
    throw v0

    .line 217
    :cond_15
    new-instance v0, Ljava/lang/NullPointerException;

    const-string v1, "Null transportName"

    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_16
    const/16 v21, 0x0

    return-object v21

    :pswitch_1
    const/16 v21, 0x0

    .line 218
    check-cast v0, Lyn/h;

    check-cast v14, Lrn/h;

    iget-object v1, v14, Lrn/h;->c:Lrn/m;

    iget-object v2, v14, Lrn/h;->a:Ljava/lang/String;

    check-cast v13, Lrn/j;

    move-object/from16 v6, p1

    check-cast v6, Landroid/database/sqlite/SQLiteDatabase;

    const/4 v8, 0x0

    .line 219
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    .line 220
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v8

    invoke-virtual {v8, v5}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    move-result-object v5

    invoke-virtual {v5}, Landroid/database/sqlite/SQLiteStatement;->simpleQueryForLong()J

    move-result-wide v8

    .line 221
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v5

    invoke-virtual {v5, v4}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    move-result-object v4

    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteStatement;->simpleQueryForLong()J

    move-result-wide v4

    mul-long/2addr v4, v8

    .line 222
    iget-object v8, v0, Lyn/h;->g:Lyn/a;

    .line 223
    iget-wide v11, v8, Lyn/a;->a:J

    cmp-long v4, v4, v11

    if-ltz v4, :cond_17

    const-wide/16 v3, 0x1

    .line 224
    invoke-virtual {v0, v3, v4, v10, v2}, Lyn/h;->g(JLun/d;Ljava/lang/String;)V

    const-wide/16 v0, -0x1

    .line 225
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    goto/16 :goto_14

    .line 226
    :cond_17
    invoke-static {v6, v13}, Lyn/h;->b(Landroid/database/sqlite/SQLiteDatabase;Lrn/j;)Ljava/lang/Long;

    move-result-object v0

    if-eqz v0, :cond_18

    .line 227
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    goto :goto_f

    .line 228
    :cond_18
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 229
    const-string v4, "backend_name"

    .line 230
    iget-object v5, v13, Lrn/j;->a:Ljava/lang/String;

    .line 231
    invoke-virtual {v0, v4, v5}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 232
    iget-object v4, v13, Lrn/j;->c:Lon/d;

    .line 233
    invoke-static {v4}, Lbo/a;->a(Lon/d;)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    const-string v5, "priority"

    invoke-virtual {v0, v5, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 234
    const-string v4, "next_request_ms"

    invoke-virtual {v0, v4, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 235
    iget-object v4, v13, Lrn/j;->b:[B

    if-eqz v4, :cond_19

    .line 236
    const-string v5, "extras"

    const/4 v12, 0x0

    invoke-static {v4, v12}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, v5, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 237
    :cond_19
    const-string v4, "transport_contexts"

    move-object/from16 v5, v21

    invoke-virtual {v6, v4, v5, v0}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    move-result-wide v9

    move-wide v4, v9

    .line 238
    :goto_f
    iget v0, v8, Lyn/a;->e:I

    .line 239
    iget-object v8, v1, Lrn/m;->b:[B

    .line 240
    array-length v9, v8

    if-gt v9, v0, :cond_1a

    const/4 v9, 0x1

    goto :goto_10

    :cond_1a
    const/4 v9, 0x0

    .line 241
    :goto_10
    new-instance v10, Landroid/content/ContentValues;

    invoke-direct {v10}, Landroid/content/ContentValues;-><init>()V

    .line 242
    const-string v11, "context_id"

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    invoke-virtual {v10, v11, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 243
    const-string v4, "transport_name"

    invoke-virtual {v10, v4, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 244
    iget-wide v4, v14, Lrn/h;->d:J

    .line 245
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    const-string v4, "timestamp_ms"

    invoke-virtual {v10, v4, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 246
    iget-wide v4, v14, Lrn/h;->e:J

    .line 247
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    const-string v4, "uptime_ms"

    invoke-virtual {v10, v4, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 248
    iget-object v1, v1, Lrn/m;->a:Lon/c;

    .line 249
    iget-object v1, v1, Lon/c;->a:Ljava/lang/String;

    .line 250
    const-string v2, "payload_encoding"

    invoke-virtual {v10, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 251
    const-string v1, "code"

    .line 252
    iget-object v2, v14, Lrn/h;->b:Ljava/lang/Integer;

    .line 253
    invoke-virtual {v10, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 254
    const-string v1, "num_attempts"

    invoke-virtual {v10, v1, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 255
    const-string v1, "inline"

    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v10, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    if-eqz v9, :cond_1b

    move-object v1, v8

    goto :goto_11

    :cond_1b
    const/4 v12, 0x0

    .line 256
    new-array v1, v12, [B

    :goto_11
    const-string v2, "payload"

    invoke-virtual {v10, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 257
    const-string v1, "product_id"

    .line 258
    iget-object v2, v14, Lrn/h;->g:Ljava/lang/Integer;

    .line 259
    invoke-virtual {v10, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 260
    const-string v1, "pseudonymous_id"

    .line 261
    iget-object v2, v14, Lrn/h;->h:Ljava/lang/String;

    .line 262
    invoke-virtual {v10, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 263
    const-string v1, "experiment_ids_clear_blob"

    .line 264
    iget-object v2, v14, Lrn/h;->i:[B

    .line 265
    invoke-virtual {v10, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 266
    const-string v1, "experiment_ids_encrypted_blob"

    .line 267
    iget-object v2, v14, Lrn/h;->j:[B

    .line 268
    invoke-virtual {v10, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 269
    const-string v1, "events"

    const/4 v5, 0x0

    invoke-virtual {v6, v1, v5, v10}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    move-result-wide v1

    .line 270
    const-string v4, "event_id"

    if-nez v9, :cond_1c

    .line 271
    array-length v5, v8

    int-to-double v9, v5

    int-to-double v11, v0

    div-double/2addr v9, v11

    invoke-static {v9, v10}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v9

    double-to-int v5, v9

    const/4 v12, 0x1

    :goto_12
    if-gt v12, v5, :cond_1c

    add-int/lit8 v7, v12, -0x1

    mul-int/2addr v7, v0

    mul-int v9, v12, v0

    .line 272
    array-length v10, v8

    .line 273
    invoke-static {v9, v10}, Ljava/lang/Math;->min(II)I

    move-result v9

    .line 274
    invoke-static {v8, v7, v9}, Ljava/util/Arrays;->copyOfRange([BII)[B

    move-result-object v7

    .line 275
    new-instance v9, Landroid/content/ContentValues;

    invoke-direct {v9}, Landroid/content/ContentValues;-><init>()V

    .line 276
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v10

    invoke-virtual {v9, v4, v10}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 277
    const-string v10, "sequence_num"

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-virtual {v9, v10, v11}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 278
    invoke-virtual {v9, v3, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 279
    const-string v7, "event_payloads"

    const/4 v10, 0x0

    invoke-virtual {v6, v7, v10, v9}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    add-int/lit8 v12, v12, 0x1

    goto :goto_12

    .line 280
    :cond_1c
    iget-object v0, v14, Lrn/h;->f:Ljava/util/Map;

    .line 281
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v0

    .line 282
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_13
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1d

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    .line 283
    new-instance v5, Landroid/content/ContentValues;

    invoke-direct {v5}, Landroid/content/ContentValues;-><init>()V

    .line 284
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v7

    invoke-virtual {v5, v4, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 285
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    const-string v8, "name"

    invoke-virtual {v5, v8, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 286
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    const-string v7, "value"

    invoke-virtual {v5, v7, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 287
    const-string v3, "event_metadata"

    const/4 v10, 0x0

    invoke-virtual {v6, v3, v10, v5}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    goto :goto_13

    .line 288
    :cond_1d
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    :goto_14
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0xf
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c(Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Laq/j;

    .line 8
    .line 9
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ljs/b;

    .line 12
    .line 13
    check-cast p1, Ldu/e;

    .line 14
    .line 15
    :try_start_0
    invoke-virtual {v1}, Laq/j;->g()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, Ldu/e;

    .line 20
    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v1, Lb81/b;

    .line 26
    .line 27
    invoke-virtual {v1, p1}, Lb81/b;->n(Ldu/e;)Lgu/d;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 34
    .line 35
    new-instance v1, Leu/a;

    .line 36
    .line 37
    const/4 v2, 0x1

    .line 38
    invoke-direct {v1, p0, p1, v2}, Leu/a;-><init>(Ljs/b;Lgu/d;I)V

    .line 39
    .line 40
    .line 41
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Lcu/d; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    :cond_0
    return-void

    .line 45
    :catch_0
    move-exception p0

    .line 46
    const-string p1, "FirebaseRemoteConfig"

    .line 47
    .line 48
    const-string v0, "Exception publishing RolloutsState to subscriber. Continuing to listen for changes."

    .line 49
    .line 50
    invoke-static {p1, v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public d(ILt7/q0;[I)Lhr/x0;
    .locals 9

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v5, v0

    .line 4
    check-cast v5, Lj8/i;

    .line 5
    .line 6
    iget-object v0, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v7, v0

    .line 9
    check-cast v7, Ljava/lang/String;

    .line 10
    .line 11
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v8, p0

    .line 14
    check-cast v8, Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 v0, 0x0

    .line 21
    move v4, v0

    .line 22
    :goto_0
    iget v0, p2, Lt7/q0;->a:I

    .line 23
    .line 24
    if-ge v4, v0, :cond_0

    .line 25
    .line 26
    new-instance v1, Lj8/k;

    .line 27
    .line 28
    aget v6, p3, v4

    .line 29
    .line 30
    move v2, p1

    .line 31
    move-object v3, p2

    .line 32
    invoke-direct/range {v1 .. v8}, Lj8/k;-><init>(ILt7/q0;ILj8/i;ILjava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, v1}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    add-int/lit8 v4, v4, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {p0}, Lhr/e0;->i()Lhr/x0;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method public e(Landroid/bluetooth/BluetoothDevice;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 8
    .line 9
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ltechnology/cariad/cat/genx/Channel;

    .line 12
    .line 13
    invoke-static {v0, v1, p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->a(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public execute()Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lwn/a;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lrn/j;

    .line 8
    .line 9
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lrn/h;

    .line 12
    .line 13
    iget-object v2, v0, Lwn/a;->d:Lyn/d;

    .line 14
    .line 15
    check-cast v2, Lyn/h;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    iget-object v3, v1, Lrn/j;->c:Lon/d;

    .line 21
    .line 22
    iget-object v4, p0, Lrn/h;->a:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v5, v1, Lrn/j;->a:Ljava/lang/String;

    .line 25
    .line 26
    const-string v6, "TRuntime."

    .line 27
    .line 28
    const-string v7, "SQLiteEventStore"

    .line 29
    .line 30
    invoke-virtual {v6, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    const/4 v7, 0x3

    .line 35
    invoke-static {v6, v7}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 36
    .line 37
    .line 38
    move-result v7

    .line 39
    if-eqz v7, :cond_0

    .line 40
    .line 41
    new-instance v7, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string v8, "Storing event with priority="

    .line 44
    .line 45
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v3, ", name="

    .line 52
    .line 53
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v3, " for destination "

    .line 60
    .line 61
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    invoke-static {v6, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    :cond_0
    new-instance v3, Lbb/i;

    .line 75
    .line 76
    const/16 v4, 0xf

    .line 77
    .line 78
    invoke-direct {v3, v2, p0, v1, v4}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v2, v3}, Lyn/h;->d(Lyn/f;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Ljava/lang/Long;

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    iget-object p0, v0, Lwn/a;->a:Lrn/i;

    .line 91
    .line 92
    const/4 v0, 0x0

    .line 93
    const/4 v2, 0x1

    .line 94
    invoke-virtual {p0, v1, v2, v0}, Lrn/i;->z(Lrn/j;IZ)V

    .line 95
    .line 96
    .line 97
    const/4 p0, 0x0

    .line 98
    return-object p0
.end method

.method public f(Lb0/j;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt1/j0;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lh0/b0;

    .line 8
    .line 9
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lb0/x1;

    .line 12
    .line 13
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lw0/i;

    .line 16
    .line 17
    new-instance v2, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v3, "Preview transformation info updated. "

    .line 20
    .line 21
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    const-string v3, "PreviewView"

    .line 32
    .line 33
    invoke-static {v3, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v1}, Lh0/b0;->l()Lh0/z;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-interface {v1}, Lh0/z;->h()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/4 v2, 0x0

    .line 45
    const/4 v3, 0x1

    .line 46
    if-nez v1, :cond_0

    .line 47
    .line 48
    move v1, v3

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move v1, v2

    .line 51
    :goto_0
    iget-object v4, v0, Lw0/i;->g:Lw0/d;

    .line 52
    .line 53
    iget-object p0, p0, Lb0/x1;->b:Landroid/util/Size;

    .line 54
    .line 55
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    new-instance v5, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v6, "Transformation info set: "

    .line 61
    .line 62
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v6, " "

    .line 69
    .line 70
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    const-string v6, "PreviewTransform"

    .line 87
    .line 88
    invoke-static {v6, v5}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    iget-object v5, p1, Lb0/j;->a:Landroid/graphics/Rect;

    .line 92
    .line 93
    iput-object v5, v4, Lw0/d;->b:Landroid/graphics/Rect;

    .line 94
    .line 95
    iget v5, p1, Lb0/j;->b:I

    .line 96
    .line 97
    iput v5, v4, Lw0/d;->c:I

    .line 98
    .line 99
    iget v5, p1, Lb0/j;->c:I

    .line 100
    .line 101
    iput v5, v4, Lw0/d;->e:I

    .line 102
    .line 103
    iput-object p0, v4, Lw0/d;->a:Landroid/util/Size;

    .line 104
    .line 105
    iput-boolean v1, v4, Lw0/d;->f:Z

    .line 106
    .line 107
    iget-boolean p0, p1, Lb0/j;->d:Z

    .line 108
    .line 109
    iput-boolean p0, v4, Lw0/d;->g:Z

    .line 110
    .line 111
    iget-object p0, p1, Lb0/j;->e:Landroid/graphics/Matrix;

    .line 112
    .line 113
    iput-object p0, v4, Lw0/d;->d:Landroid/graphics/Matrix;

    .line 114
    .line 115
    const/4 p0, -0x1

    .line 116
    if-eq v5, p0, :cond_2

    .line 117
    .line 118
    iget-object p0, v0, Lw0/i;->e:Landroidx/core/app/a0;

    .line 119
    .line 120
    if-eqz p0, :cond_1

    .line 121
    .line 122
    instance-of p0, p0, Lw0/p;

    .line 123
    .line 124
    if-eqz p0, :cond_1

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_1
    iput-boolean v2, v0, Lw0/i;->h:Z

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_2
    :goto_1
    iput-boolean v3, v0, Lw0/i;->h:Z

    .line 131
    .line 132
    :goto_2
    invoke-virtual {v0}, Lw0/i;->a()V

    .line 133
    .line 134
    .line 135
    return-void
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 7

    .line 1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/String;

    .line 8
    .line 9
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lcom/google/firebase/messaging/x;

    .line 12
    .line 13
    check-cast p1, Ljava/lang/String;

    .line 14
    .line 15
    iget-object v2, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 16
    .line 17
    invoke-static {v2}, Lcom/google/firebase/messaging/FirebaseMessaging;->d(Landroid/content/Context;)La0/j;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->e()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    iget-object v4, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->h:Lcom/google/firebase/messaging/r;

    .line 26
    .line 27
    invoke-virtual {v4}, Lcom/google/firebase/messaging/r;->b()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    monitor-enter v2

    .line 32
    :try_start_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 33
    .line 34
    .line 35
    move-result-wide v5

    .line 36
    invoke-static {v5, v6, p1, v4}, Lcom/google/firebase/messaging/x;->a(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    if-nez v4, :cond_0

    .line 41
    .line 42
    monitor-exit v2

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    :try_start_1
    iget-object v5, v2, La0/j;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v5, Landroid/content/SharedPreferences;

    .line 47
    .line 48
    invoke-interface {v5}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    invoke-static {v3, v1}, La0/j;->U(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-interface {v5, v1, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 57
    .line 58
    .line 59
    invoke-interface {v5}, Landroid/content/SharedPreferences$Editor;->commit()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 60
    .line 61
    .line 62
    monitor-exit v2

    .line 63
    :goto_0
    if-eqz p0, :cond_1

    .line 64
    .line 65
    iget-object p0, p0, Lcom/google/firebase/messaging/x;->a:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-nez p0, :cond_3

    .line 72
    .line 73
    :cond_1
    const-string p0, "FirebaseMessaging"

    .line 74
    .line 75
    const-string v1, "[DEFAULT]"

    .line 76
    .line 77
    iget-object v2, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 78
    .line 79
    invoke-virtual {v2}, Lsr/f;->a()V

    .line 80
    .line 81
    .line 82
    iget-object v3, v2, Lsr/f;->b:Ljava/lang/String;

    .line 83
    .line 84
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    const/4 v1, 0x3

    .line 91
    invoke-static {p0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-eqz v1, :cond_2

    .line 96
    .line 97
    new-instance v1, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v3, "Invoking onNewToken for app: "

    .line 100
    .line 101
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v2}, Lsr/f;->a()V

    .line 105
    .line 106
    .line 107
    iget-object v2, v2, Lsr/f;->b:Ljava/lang/String;

    .line 108
    .line 109
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-static {p0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 117
    .line 118
    .line 119
    :cond_2
    new-instance p0, Landroid/content/Intent;

    .line 120
    .line 121
    const-string v1, "com.google.firebase.messaging.NEW_TOKEN"

    .line 122
    .line 123
    invoke-direct {p0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string v1, "token"

    .line 127
    .line 128
    invoke-virtual {p0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 129
    .line 130
    .line 131
    new-instance v1, Lcom/google/firebase/messaging/j;

    .line 132
    .line 133
    iget-object v0, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 134
    .line 135
    invoke-direct {v1, v0}, Lcom/google/firebase/messaging/j;-><init>(Landroid/content/Context;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v1, p0}, Lcom/google/firebase/messaging/j;->b(Landroid/content/Intent;)Laq/t;

    .line 139
    .line 140
    .line 141
    :cond_3
    invoke-static {p1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    return-object p0

    .line 146
    :catchall_0
    move-exception p0

    .line 147
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 148
    throw p0
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lbb/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ly4/k;

    .line 9
    .line 10
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lj0/h;

    .line 13
    .line 14
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ljava/util/Collection;

    .line 17
    .line 18
    new-instance v2, La0/d;

    .line 19
    .line 20
    const/16 v3, 0x16

    .line 21
    .line 22
    invoke-direct {v2, v0, v3}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v1, v2}, Ly4/h;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 26
    .line 27
    .line 28
    new-instance v2, Lh0/u0;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {v2, p1, v3}, Lh0/u0;-><init>(Ly4/h;I)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lk0/g;

    .line 35
    .line 36
    invoke-direct {p1, v3, v0, v2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v1, p1}, Ly4/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 40
    .line 41
    .line 42
    new-instance p1, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v0, "surfaceList["

    .line 45
    .line 46
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string p0, "]"

    .line 53
    .line 54
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_0
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lpx0/g;

    .line 65
    .line 66
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v1, Lvy0/c0;

    .line 69
    .line 70
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lrx0/i;

    .line 73
    .line 74
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 75
    .line 76
    invoke-interface {v0, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    check-cast v2, Lvy0/i1;

    .line 81
    .line 82
    new-instance v3, La0/d;

    .line 83
    .line 84
    const/16 v4, 0xf

    .line 85
    .line 86
    invoke-direct {v3, v2, v4}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 87
    .line 88
    .line 89
    sget-object v2, Leb/k;->d:Leb/k;

    .line 90
    .line 91
    invoke-virtual {p1, v2, v3}, Ly4/h;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 92
    .line 93
    .line 94
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    new-instance v2, Le1/e;

    .line 99
    .line 100
    const/4 v3, 0x0

    .line 101
    invoke-direct {v2, p0, p1, v3}, Le1/e;-><init>(Lay0/n;Ly4/h;Lkotlin/coroutines/Continuation;)V

    .line 102
    .line 103
    .line 104
    const/4 p0, 0x1

    .line 105
    invoke-static {v0, v3, v1, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0

    .line 110
    :pswitch_1
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 113
    .line 114
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v1, Ljava/lang/String;

    .line 117
    .line 118
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast p0, Lay0/a;

    .line 121
    .line 122
    new-instance v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 123
    .line 124
    const/4 v3, 0x0

    .line 125
    invoke-direct {v2, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 126
    .line 127
    .line 128
    new-instance v3, Leb/p;

    .line 129
    .line 130
    const/4 v4, 0x0

    .line 131
    invoke-direct {v3, v2, v4}, Leb/p;-><init>(Ljava/util/concurrent/atomic/AtomicBoolean;I)V

    .line 132
    .line 133
    .line 134
    sget-object v4, Leb/k;->d:Leb/k;

    .line 135
    .line 136
    invoke-virtual {p1, v4, v3}, Ly4/h;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 137
    .line 138
    .line 139
    new-instance v3, Leb/q;

    .line 140
    .line 141
    const/4 v4, 0x0

    .line 142
    invoke-direct {v3, v2, p1, p0, v4}, Leb/q;-><init>(Ljava/util/concurrent/atomic/AtomicBoolean;Ly4/h;Lay0/a;I)V

    .line 143
    .line 144
    .line 145
    invoke-interface {v0, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 146
    .line 147
    .line 148
    return-object v1

    .line 149
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lbb/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Laq/k;

    .line 9
    .line 10
    iget-object v1, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 13
    .line 14
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Laq/a;

    .line 17
    .line 18
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {v0, p0}, Laq/k;->d(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {v0, p0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    const/4 p1, 0x1

    .line 47
    invoke-virtual {v1, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    invoke-virtual {p0}, Laq/a;->k()V

    .line 54
    .line 55
    .line 56
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 57
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_0
    iget-object p1, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p1, Ldu/l;

    .line 65
    .line 66
    iget-object v0, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Laq/j;

    .line 69
    .line 70
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Laq/j;

    .line 73
    .line 74
    invoke-virtual {v0}, Laq/j;->i()Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-nez v1, :cond_3

    .line 79
    .line 80
    new-instance p0, Lcu/c;

    .line 81
    .line 82
    const-string p1, "Firebase Installations failed to get installation auth token for config update listener connection."

    .line 83
    .line 84
    invoke-virtual {v0}, Laq/j;->f()Ljava/lang/Exception;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-direct {p0, p1, v0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 89
    .line 90
    .line 91
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    goto :goto_2

    .line 96
    :cond_3
    invoke-virtual {p0}, Laq/j;->i()Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-nez v1, :cond_4

    .line 101
    .line 102
    new-instance p1, Lcu/c;

    .line 103
    .line 104
    const-string v0, "Firebase Installations failed to get installation ID for config update listener connection."

    .line 105
    .line 106
    invoke-virtual {p0}, Laq/j;->f()Ljava/lang/Exception;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-direct {p1, v0, p0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 111
    .line 112
    .line 113
    invoke-static {p1}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    goto :goto_2

    .line 118
    :cond_4
    :try_start_0
    new-instance v1, Ljava/net/URL;

    .line 119
    .line 120
    iget-object v2, p1, Ldu/l;->n:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {p1, v2}, Ldu/l;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-direct {v1, v2}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/net/MalformedURLException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :catch_0
    :try_start_1
    const-string v1, "FirebaseRemoteConfig"

    .line 131
    .line 132
    const-string v2, "URL is malformed"

    .line 133
    .line 134
    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 135
    .line 136
    .line 137
    const/4 v1, 0x0

    .line 138
    :goto_1
    invoke-virtual {v1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    check-cast v1, Ljava/net/HttpURLConnection;

    .line 143
    .line 144
    invoke-virtual {v0}, Laq/j;->g()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    check-cast v0, Lht/a;

    .line 149
    .line 150
    iget-object v0, v0, Lht/a;->a:Ljava/lang/String;

    .line 151
    .line 152
    invoke-virtual {p0}, Laq/j;->g()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    check-cast p0, Ljava/lang/String;

    .line 157
    .line 158
    invoke-virtual {p1, v1, p0, v0}, Ldu/l;->i(Ljava/net/HttpURLConnection;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 159
    .line 160
    .line 161
    invoke-static {v1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    goto :goto_2

    .line 166
    :catch_1
    move-exception p0

    .line 167
    new-instance p1, Lcu/c;

    .line 168
    .line 169
    const-string v0, "Failed to open HTTP stream connection"

    .line 170
    .line 171
    invoke-direct {p1, v0, p0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 172
    .line 173
    .line 174
    invoke-static {p1}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    :goto_2
    return-object p0

    .line 179
    :pswitch_1
    iget-object p1, p0, Lbb/i;->e:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast p1, Lcu/b;

    .line 182
    .line 183
    iget-object v0, p0, Lbb/i;->f:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast v0, Laq/j;

    .line 186
    .line 187
    iget-object p0, p0, Lbb/i;->g:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast p0, Laq/j;

    .line 190
    .line 191
    invoke-virtual {v0}, Laq/j;->i()Z

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    if-eqz v1, :cond_8

    .line 196
    .line 197
    invoke-virtual {v0}, Laq/j;->g()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    if-nez v1, :cond_5

    .line 202
    .line 203
    goto :goto_4

    .line 204
    :cond_5
    invoke-virtual {v0}, Laq/j;->g()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    check-cast v0, Ldu/e;

    .line 209
    .line 210
    invoke-virtual {p0}, Laq/j;->i()Z

    .line 211
    .line 212
    .line 213
    move-result v1

    .line 214
    if-eqz v1, :cond_7

    .line 215
    .line 216
    invoke-virtual {p0}, Laq/j;->g()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    check-cast p0, Ldu/e;

    .line 221
    .line 222
    if-eqz p0, :cond_7

    .line 223
    .line 224
    iget-object v1, v0, Ldu/e;->c:Ljava/util/Date;

    .line 225
    .line 226
    iget-object p0, p0, Ldu/e;->c:Ljava/util/Date;

    .line 227
    .line 228
    invoke-virtual {v1, p0}, Ljava/util/Date;->equals(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    move-result p0

    .line 232
    if-nez p0, :cond_6

    .line 233
    .line 234
    goto :goto_3

    .line 235
    :cond_6
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 236
    .line 237
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    goto :goto_5

    .line 242
    :cond_7
    :goto_3
    iget-object p0, p1, Lcu/b;->e:Ldu/c;

    .line 243
    .line 244
    invoke-virtual {p0, v0}, Ldu/c;->d(Ldu/e;)Laq/t;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    iget-object v0, p1, Lcu/b;->c:Ljava/util/concurrent/Executor;

    .line 249
    .line 250
    new-instance v1, Lcu/a;

    .line 251
    .line 252
    invoke-direct {v1, p1}, Lcu/a;-><init>(Lcu/b;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {p0, v0, v1}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    goto :goto_5

    .line 260
    :cond_8
    :goto_4
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 261
    .line 262
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    :goto_5
    return-object p0

    .line 267
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
