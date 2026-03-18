.class public final Lcq/y0;
.super Lcq/m1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final f:Ljava/lang/ref/WeakReference;

.field public final g:Ljava/lang/ref/WeakReference;


# direct methods
.method public constructor <init>(Ljava/util/HashMap;Ljava/lang/Object;La0/j;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcq/y0;->e:I

    .line 1
    invoke-direct {p0, p3}, Lcq/m1;-><init>(Llo/e;)V

    new-instance p3, Ljava/lang/ref/WeakReference;

    .line 2
    invoke-direct {p3, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object p3, p0, Lcq/y0;->f:Ljava/lang/ref/WeakReference;

    new-instance p1, Ljava/lang/ref/WeakReference;

    .line 3
    invoke-direct {p1, p2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lcq/y0;->g:Ljava/lang/ref/WeakReference;

    return-void
.end method

.method public constructor <init>(Ljava/util/HashMap;Ljava/lang/Object;Laq/s;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcq/y0;->e:I

    .line 4
    invoke-direct {p0, p3}, Lcq/m1;-><init>(Llo/e;)V

    new-instance p3, Ljava/lang/ref/WeakReference;

    .line 5
    invoke-direct {p3, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object p3, p0, Lcq/y0;->f:Ljava/lang/ref/WeakReference;

    new-instance p1, Ljava/lang/ref/WeakReference;

    .line 6
    invoke-direct {p1, p2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lcq/y0;->g:Ljava/lang/ref/WeakReference;

    return-void
.end method


# virtual methods
.method public final p(Lcom/google/android/gms/common/api/Status;)V
    .locals 4

    .line 1
    iget v0, p0, Lcq/y0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcq/y0;->f:Ljava/lang/ref/WeakReference;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Ljava/util/Map;

    .line 13
    .line 14
    iget-object v1, p0, Lcq/y0;->g:Ljava/lang/ref/WeakReference;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    iget v2, p1, Lcom/google/android/gms/common/api/Status;->d:I

    .line 24
    .line 25
    const/16 v3, 0xfa2

    .line 26
    .line 27
    if-ne v2, v3, :cond_1

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    monitor-enter v0

    .line 34
    :try_start_0
    invoke-interface {v0, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lcq/u1;

    .line 39
    .line 40
    if-eqz v1, :cond_0

    .line 41
    .line 42
    invoke-virtual {v1}, Lcq/u1;->T()V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    :goto_0
    monitor-exit v0

    .line 49
    goto :goto_2

    .line 50
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    throw p0

    .line 52
    :cond_1
    :goto_2
    iget-object v0, p0, Lcq/m1;->d:Llo/e;

    .line 53
    .line 54
    if-eqz v0, :cond_2

    .line 55
    .line 56
    invoke-interface {v0, p1}, Llo/e;->z(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    const/4 p1, 0x0

    .line 60
    iput-object p1, p0, Lcq/m1;->d:Llo/e;

    .line 61
    .line 62
    :cond_2
    return-void

    .line 63
    :pswitch_0
    iget-object v0, p0, Lcq/y0;->f:Ljava/lang/ref/WeakReference;

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, Ljava/util/Map;

    .line 70
    .line 71
    iget-object v1, p0, Lcq/y0;->g:Ljava/lang/ref/WeakReference;

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-nez v2, :cond_4

    .line 85
    .line 86
    if-eqz v0, :cond_4

    .line 87
    .line 88
    if-eqz v1, :cond_4

    .line 89
    .line 90
    monitor-enter v0

    .line 91
    :try_start_1
    invoke-interface {v0, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    check-cast v1, Lcq/u1;

    .line 96
    .line 97
    if-eqz v1, :cond_3

    .line 98
    .line 99
    invoke-virtual {v1}, Lcq/u1;->T()V

    .line 100
    .line 101
    .line 102
    goto :goto_3

    .line 103
    :catchall_1
    move-exception p0

    .line 104
    goto :goto_4

    .line 105
    :cond_3
    :goto_3
    monitor-exit v0

    .line 106
    goto :goto_5

    .line 107
    :goto_4
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 108
    throw p0

    .line 109
    :cond_4
    :goto_5
    iget-object v0, p0, Lcq/m1;->d:Llo/e;

    .line 110
    .line 111
    if-eqz v0, :cond_5

    .line 112
    .line 113
    invoke-interface {v0, p1}, Llo/e;->z(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    const/4 p1, 0x0

    .line 117
    iput-object p1, p0, Lcq/m1;->d:Llo/e;

    .line 118
    .line 119
    :cond_5
    return-void

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
