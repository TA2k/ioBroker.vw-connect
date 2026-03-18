.class public final Le3/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/ComponentCallbacks2;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Le3/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le3/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private final a(Landroid/content/res/Configuration;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final b()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 1

    .line 1
    iget v0, p0, Le3/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "newConfig"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Le3/c;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lvv0/d;

    .line 15
    .line 16
    monitor-enter p0

    .line 17
    :try_start_0
    iget-object p1, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Ljava/lang/ref/WeakReference;

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    check-cast p1, Lyl/r;

    .line 26
    .line 27
    if-eqz p1, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {p0}, Lvv0/d;->k()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    .line 33
    :goto_0
    monitor-exit p0

    .line 34
    return-void

    .line 35
    :catchall_0
    move-exception p1

    .line 36
    monitor-exit p0

    .line 37
    throw p1

    .line 38
    :pswitch_1
    return-void

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final onLowMemory()V
    .locals 1

    .line 1
    iget v0, p0, Le3/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le3/c;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lqp/h;

    .line 9
    .line 10
    invoke-virtual {p0}, Lqp/h;->a()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    const/16 v0, 0x50

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Le3/c;->onTrimMemory(I)V

    .line 17
    .line 18
    .line 19
    :pswitch_1
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final onTrimMemory(I)V
    .locals 5

    .line 1
    iget v0, p0, Le3/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le3/c;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lqp/h;

    .line 9
    .line 10
    invoke-virtual {p0}, Lqp/h;->a()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Le3/c;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lvv0/d;

    .line 17
    .line 18
    monitor-enter p0

    .line 19
    :try_start_0
    iget-object v0, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Ljava/lang/ref/WeakReference;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lyl/r;

    .line 28
    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    iget-object v1, v0, Lyl/r;->a:Lyl/o;

    .line 32
    .line 33
    const/16 v2, 0x28

    .line 34
    .line 35
    if-lt p1, v2, :cond_0

    .line 36
    .line 37
    invoke-virtual {v0}, Lyl/r;->c()Lhm/d;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    if-eqz p1, :cond_3

    .line 42
    .line 43
    iget-object v0, p1, Lhm/d;->c:Ljava/lang/Object;

    .line 44
    .line 45
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 46
    :try_start_1
    iget-object v1, p1, Lhm/d;->a:Lh6/j;

    .line 47
    .line 48
    iget-object v1, v1, Lh6/j;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v1, Lc1/i2;

    .line 51
    .line 52
    const-wide/16 v2, -0x1

    .line 53
    .line 54
    invoke-virtual {v1, v2, v3}, Lc1/i2;->g(J)V

    .line 55
    .line 56
    .line 57
    iget-object p1, p1, Lhm/d;->b:Lhm/g;

    .line 58
    .line 59
    const/4 v1, 0x0

    .line 60
    iput v1, p1, Lhm/g;->b:I

    .line 61
    .line 62
    iget-object p1, p1, Lhm/g;->a:Ljava/util/LinkedHashMap;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->clear()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 65
    .line 66
    .line 67
    :try_start_2
    monitor-exit v0

    .line 68
    goto :goto_0

    .line 69
    :catchall_0
    move-exception p1

    .line 70
    monitor-exit v0

    .line 71
    throw p1

    .line 72
    :catchall_1
    move-exception p1

    .line 73
    goto :goto_1

    .line 74
    :cond_0
    const/16 v2, 0x14

    .line 75
    .line 76
    if-lt p1, v2, :cond_1

    .line 77
    .line 78
    iget-object p1, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p1, Lsm/a;

    .line 81
    .line 82
    iget-object v0, v1, Lyl/o;->a:Landroid/content/Context;

    .line 83
    .line 84
    invoke-virtual {p1, v0}, Lsm/a;->a(Landroid/content/Context;)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_1
    const/16 v1, 0xa

    .line 89
    .line 90
    if-lt p1, v1, :cond_3

    .line 91
    .line 92
    invoke-virtual {v0}, Lyl/r;->c()Lhm/d;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    if-eqz p1, :cond_3

    .line 97
    .line 98
    iget-object v0, p1, Lhm/d;->c:Ljava/lang/Object;

    .line 99
    .line 100
    monitor-enter v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 101
    :try_start_3
    iget-object v1, p1, Lhm/d;->a:Lh6/j;

    .line 102
    .line 103
    iget-object v1, v1, Lh6/j;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v1, Lc1/i2;

    .line 106
    .line 107
    invoke-virtual {v1}, Lc1/i2;->c()J

    .line 108
    .line 109
    .line 110
    move-result-wide v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 111
    :try_start_4
    monitor-exit v0

    .line 112
    const/4 v0, 0x2

    .line 113
    int-to-long v3, v0

    .line 114
    div-long/2addr v1, v3

    .line 115
    iget-object v0, p1, Lhm/d;->c:Ljava/lang/Object;

    .line 116
    .line 117
    monitor-enter v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 118
    :try_start_5
    iget-object p1, p1, Lhm/d;->a:Lh6/j;

    .line 119
    .line 120
    iget-object p1, p1, Lh6/j;->f:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast p1, Lc1/i2;

    .line 123
    .line 124
    invoke-virtual {p1, v1, v2}, Lc1/i2;->g(J)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 125
    .line 126
    .line 127
    :try_start_6
    monitor-exit v0

    .line 128
    goto :goto_0

    .line 129
    :catchall_2
    move-exception p1

    .line 130
    monitor-exit v0

    .line 131
    throw p1

    .line 132
    :catchall_3
    move-exception p1

    .line 133
    monitor-exit v0

    .line 134
    throw p1

    .line 135
    :cond_2
    invoke-virtual {p0}, Lvv0/d;->k()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 136
    .line 137
    .line 138
    :cond_3
    :goto_0
    monitor-exit p0

    .line 139
    return-void

    .line 140
    :goto_1
    monitor-exit p0

    .line 141
    throw p1

    .line 142
    :pswitch_1
    const/16 v0, 0x28

    .line 143
    .line 144
    if-lt p1, v0, :cond_4

    .line 145
    .line 146
    iget-object p0, p0, Le3/c;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast p0, Le3/e;

    .line 149
    .line 150
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    :cond_4
    return-void

    .line 154
    nop

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
