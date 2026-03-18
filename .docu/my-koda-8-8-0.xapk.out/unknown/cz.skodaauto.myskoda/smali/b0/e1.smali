.class public final Lb0/e1;
.super Lh0/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb0/e1;->a:I

    iput-object p1, p0, Lb0/e1;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lt0/h;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lb0/e1;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Lb0/e1;->b:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public b(ILh0/s;)V
    .locals 7

    .line 1
    iget v0, p0, Lb0/e1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    return-void

    .line 7
    :pswitch_1
    iget-object p0, p0, Lb0/e1;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/lang/ref/WeakReference;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lt0/h;

    .line 16
    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Lt0/h;->d:Ljava/util/HashSet;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lb0/z1;

    .line 36
    .line 37
    iget-object v0, v0, Lb0/z1;->n:Lh0/z1;

    .line 38
    .line 39
    iget-object v1, v0, Lh0/z1;->g:Lh0/o0;

    .line 40
    .line 41
    iget-object v1, v1, Lh0/o0;->d:Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-eqz v2, :cond_0

    .line 52
    .line 53
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    check-cast v2, Lh0/m;

    .line 58
    .line 59
    new-instance v3, Lh6/j;

    .line 60
    .line 61
    iget-object v4, v0, Lh0/z1;->g:Lh0/o0;

    .line 62
    .line 63
    iget-object v4, v4, Lh0/o0;->f:Lh0/j2;

    .line 64
    .line 65
    const-wide/16 v5, -0x1

    .line 66
    .line 67
    invoke-direct {v3, p2, v4, v5, v6}, Lh6/j;-><init>(Lh0/s;Lh0/j2;J)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v2, p1, v3}, Lh0/m;->b(ILh0/s;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    return-void

    .line 75
    :pswitch_2
    iget-object p0, p0, Lb0/e1;->b:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Lb0/f1;

    .line 78
    .line 79
    iget-object p1, p0, Lb0/f1;->d:Ljava/lang/Object;

    .line 80
    .line 81
    monitor-enter p1

    .line 82
    :try_start_0
    iget-boolean v0, p0, Lb0/f1;->h:Z

    .line 83
    .line 84
    if-eqz v0, :cond_2

    .line 85
    .line 86
    monitor-exit p1

    .line 87
    goto :goto_1

    .line 88
    :catchall_0
    move-exception p0

    .line 89
    goto :goto_2

    .line 90
    :cond_2
    iget-object v0, p0, Lb0/f1;->l:Landroid/util/LongSparseArray;

    .line 91
    .line 92
    invoke-interface {p2}, Lh0/s;->c()J

    .line 93
    .line 94
    .line 95
    move-result-wide v1

    .line 96
    new-instance v3, Ll0/c;

    .line 97
    .line 98
    invoke-direct {v3, p2}, Ll0/c;-><init>(Lh0/s;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, v1, v2, v3}, Landroid/util/LongSparseArray;->put(JLjava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0}, Lb0/f1;->k()V

    .line 105
    .line 106
    .line 107
    monitor-exit p1

    .line 108
    :goto_1
    return-void

    .line 109
    :goto_2
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 110
    throw p0

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public d(I)V
    .locals 2

    .line 1
    iget p1, p0, Lb0/e1;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    new-instance v0, La0/d;

    .line 12
    .line 13
    const/16 v1, 0x11

    .line 14
    .line 15
    invoke-direct {v0, p0, v1}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, v0}, Lj0/c;->execute(Ljava/lang/Runnable;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
