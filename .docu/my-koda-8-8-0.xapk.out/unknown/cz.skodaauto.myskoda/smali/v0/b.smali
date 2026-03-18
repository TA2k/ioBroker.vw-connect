.class public final Lv0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/w;
.implements Lb0/k;


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Landroidx/lifecycle/x;

.field public final f:Ll0/g;

.field public g:Z

.field public h:Lb0/d1;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/x;Ll0/g;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Lv0/b;->g:Z

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    iput-object v0, p0, Lv0/b;->h:Lb0/d1;

    .line 16
    .line 17
    iput-object p1, p0, Lv0/b;->e:Landroidx/lifecycle/x;

    .line 18
    .line 19
    iput-object p2, p0, Lv0/b;->f:Ll0/g;

    .line 20
    .line 21
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sget-object v1, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-ltz v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {p2}, Ll0/g;->r()V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {p2}, Ll0/g;->v()V

    .line 42
    .line 43
    .line 44
    :goto_0
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-virtual {p1, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final a()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 2
    .line 3
    iget-object p0, p0, Ll0/g;->d:Lh0/d;

    .line 4
    .line 5
    iget-object p0, p0, Lh0/d;->e:Lh0/c;

    .line 6
    .line 7
    return-object p0
.end method

.method public final e(Lb0/d1;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lv0/b;->h:Lb0/d1;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    iput-object p1, p0, Lv0/b;->h:Lb0/d1;

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    goto/16 :goto_1

    .line 13
    .line 14
    :cond_0
    iget-boolean v2, p1, Lb0/d1;->d:Z

    .line 15
    .line 16
    if-eqz v2, :cond_2

    .line 17
    .line 18
    iget-boolean v1, v1, Lb0/d1;->d:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    new-instance v1, Ljava/util/ArrayList;

    .line 23
    .line 24
    iget-object v2, p0, Lv0/b;->h:Lb0/d1;

    .line 25
    .line 26
    iget-object v2, v2, Lb0/d1;->g:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v2, Ljava/util/List;

    .line 29
    .line 30
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 31
    .line 32
    .line 33
    iget-object v2, p1, Lb0/d1;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v2, Ljava/util/List;

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 38
    .line 39
    .line 40
    new-instance v2, Lb0/d1;

    .line 41
    .line 42
    iget-object v3, p1, Lb0/d1;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v3, Ljava/util/List;

    .line 45
    .line 46
    invoke-direct {v2, v1, v3}, Lb0/d1;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 47
    .line 48
    .line 49
    iput-object v2, p0, Lv0/b;->h:Lb0/d1;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "Cannot bind use cases when a SessionConfig is already bound to this LifecycleOwner. Please unbind first"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget-boolean v1, v1, Lb0/d1;->d:Z

    .line 61
    .line 62
    if-nez v1, :cond_3

    .line 63
    .line 64
    iput-object p1, p0, Lv0/b;->h:Lb0/d1;

    .line 65
    .line 66
    iget-object v1, p0, Lv0/b;->f:Ll0/g;

    .line 67
    .line 68
    invoke-virtual {v1}, Ll0/g;->z()Ljava/util/List;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-virtual {v1, v2}, Ll0/g;->C(Ljava/util/ArrayList;)V

    .line 75
    .line 76
    .line 77
    :goto_0
    iget-object v1, p0, Lv0/b;->f:Ll0/g;

    .line 78
    .line 79
    iget-object v1, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 80
    .line 81
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 82
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 83
    :try_start_2
    iget-object v1, p0, Lv0/b;->f:Ll0/g;

    .line 84
    .line 85
    iget-object v2, p1, Lb0/d1;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v2, Ljava/util/List;

    .line 88
    .line 89
    iget-object v3, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 90
    .line 91
    monitor-enter v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 92
    :try_start_3
    iput-object v2, v1, Ll0/g;->k:Ljava/util/List;

    .line 93
    .line 94
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 95
    :try_start_4
    iget-object v1, p0, Lv0/b;->f:Ll0/g;

    .line 96
    .line 97
    iget-object v1, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 98
    .line 99
    monitor-enter v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 100
    :try_start_5
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 101
    :try_start_6
    iget-object v1, p0, Lv0/b;->f:Ll0/g;

    .line 102
    .line 103
    iget-object v2, p1, Lb0/d1;->h:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v2, Landroid/util/Range;

    .line 106
    .line 107
    iget-object v3, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 108
    .line 109
    monitor-enter v3
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 110
    :try_start_7
    iput-object v2, v1, Ll0/g;->l:Landroid/util/Range;

    .line 111
    .line 112
    monitor-exit v3
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 113
    :try_start_8
    invoke-virtual {p0}, Lv0/b;->a()Lh0/z;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Lh0/z;

    .line 118
    .line 119
    const-string v2, "cameraInfoInternal"

    .line 120
    .line 121
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p1, v1}, Lgv/a;->l(Lb0/d1;Lh0/z;)Ld0/c;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    iget-object v2, p1, Lb0/d1;->k:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v2, Lj0/c;

    .line 131
    .line 132
    new-instance v3, Lno/nordicsemi/android/ble/o0;

    .line 133
    .line 134
    const/16 v4, 0x15

    .line 135
    .line 136
    invoke-direct {v3, v4, v1, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v2, v3}, Lj0/c;->execute(Ljava/lang/Runnable;)V

    .line 140
    .line 141
    .line 142
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 143
    .line 144
    iget-object p1, p1, Lb0/d1;->g:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast p1, Ljava/util/List;

    .line 147
    .line 148
    invoke-virtual {p0, p1, v1}, Ll0/g;->e(Ljava/util/Collection;Ld0/c;)V

    .line 149
    .line 150
    .line 151
    monitor-exit v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 152
    return-void

    .line 153
    :catchall_1
    move-exception p0

    .line 154
    :try_start_9
    monitor-exit v3
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 155
    :try_start_a
    throw p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 156
    :catchall_2
    move-exception p0

    .line 157
    :try_start_b
    monitor-exit v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    .line 158
    :try_start_c
    throw p0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 159
    :catchall_3
    move-exception p0

    .line 160
    :try_start_d
    monitor-exit v3
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_3

    .line 161
    :try_start_e
    throw p0
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_0

    .line 162
    :catchall_4
    move-exception p0

    .line 163
    :try_start_f
    monitor-exit v1
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 164
    :try_start_10
    throw p0

    .line 165
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 166
    .line 167
    const-string p1, "Cannot bind the SessionConfig when use cases are bound to this LifecycleOwner already. Please unbind first"

    .line 168
    .line 169
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :goto_1
    monitor-exit v0
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_0

    .line 174
    throw p0
.end method

.method public final m()Landroidx/lifecycle/x;
    .locals 1

    .line 1
    iget-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lv0/b;->e:Landroidx/lifecycle/x;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public onDestroy(Landroidx/lifecycle/x;)V
    .locals 1
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object p1, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 5
    .line 6
    invoke-virtual {p0}, Ll0/g;->z()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ll0/g;->C(Ljava/util/ArrayList;)V

    .line 13
    .line 14
    .line 15
    monitor-exit p1

    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public onPause(Landroidx/lifecycle/x;)V
    .locals 0
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_PAUSE:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    const/4 p1, 0x0

    .line 2
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 3
    .line 4
    iget-object p0, p0, Ll0/g;->d:Lh0/d;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lh0/d;->j(Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public onResume(Landroidx/lifecycle/x;)V
    .locals 0
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_RESUME:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 3
    .line 4
    iget-object p0, p0, Ll0/g;->d:Lh0/d;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lh0/d;->j(Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public onStart(Landroidx/lifecycle/x;)V
    .locals 1
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object p1, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-boolean v0, p0, Lv0/b;->g:Z

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 9
    .line 10
    invoke-virtual {p0}, Ll0/g;->r()V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    :goto_0
    monitor-exit p1

    .line 17
    return-void

    .line 18
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public onStop(Landroidx/lifecycle/x;)V
    .locals 1
    .annotation runtime Landroidx/lifecycle/k0;
        value = .enum Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;
    .end annotation

    .line 1
    iget-object p1, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-boolean v0, p0, Lv0/b;->g:Z

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 9
    .line 10
    invoke-virtual {p0}, Ll0/g;->v()V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    :goto_0
    monitor-exit p1

    .line 17
    return-void

    .line 18
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public final r()Ljava/util/List;
    .locals 1

    .line 1
    iget-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lv0/b;->f:Ll0/g;

    .line 5
    .line 6
    invoke-virtual {p0}, Ll0/g;->z()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    monitor-exit v0

    .line 15
    return-object p0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    throw p0
.end method

.method public final s()V
    .locals 2

    .line 1
    iget-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lv0/b;->g:Z

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v1, p0, Lv0/b;->e:Landroidx/lifecycle/x;

    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lv0/b;->onStop(Landroidx/lifecycle/x;)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    iput-boolean v1, p0, Lv0/b;->g:Z

    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method

.method public final t()V
    .locals 3

    .line 1
    iget-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lv0/b;->f:Ll0/g;

    .line 5
    .line 6
    invoke-virtual {v1}, Ll0/g;->z()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    check-cast v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ll0/g;->C(Ljava/util/ArrayList;)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    iput-object v1, p0, Lv0/b;->h:Lb0/d1;

    .line 17
    .line 18
    monitor-exit v0

    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method

.method public final u()V
    .locals 4

    .line 1
    iget-object v0, p0, Lv0/b;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lv0/b;->g:Z

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v1, 0x0

    .line 13
    iput-boolean v1, p0, Lv0/b;->g:Z

    .line 14
    .line 15
    iget-object v2, p0, Lv0/b;->e:Landroidx/lifecycle/x;

    .line 16
    .line 17
    invoke-interface {v2}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v2}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    sget-object v3, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 26
    .line 27
    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-ltz v2, :cond_1

    .line 32
    .line 33
    const/4 v1, 0x1

    .line 34
    :cond_1
    if-eqz v1, :cond_2

    .line 35
    .line 36
    iget-object v1, p0, Lv0/b;->e:Landroidx/lifecycle/x;

    .line 37
    .line 38
    invoke-virtual {p0, v1}, Lv0/b;->onStart(Landroidx/lifecycle/x;)V

    .line 39
    .line 40
    .line 41
    :cond_2
    monitor-exit v0

    .line 42
    return-void

    .line 43
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    throw p0
.end method
