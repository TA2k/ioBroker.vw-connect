.class public final Lvp/d2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic f:Lvp/j2;


# direct methods
.method public constructor <init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/d2;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 10
    .line 11
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lvp/d2;->f:Lvp/j2;

    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p2, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 21
    .line 22
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lvp/d2;->f:Lvp/j2;

    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object p2, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 32
    .line 33
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lvp/d2;->f:Lvp/j2;

    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lvp/d2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object v1, p0, Lvp/d2;->f:Lvp/j2;

    .line 10
    .line 11
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Lvp/g1;

    .line 14
    .line 15
    iget-object v2, v1, Lvp/g1;->g:Lvp/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lvp/g1;->q()Lvp/h0;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1}, Lvp/h0;->g0()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    sget-object v3, Lvp/z;->d0:Lvp/y;

    .line 26
    .line 27
    invoke-virtual {v2, v1, v3}, Lvp/h;->i0(Ljava/lang/String;Lvp/y;)I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 36
    .line 37
    .line 38
    :try_start_1
    iget-object p0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 41
    .line 42
    .line 43
    monitor-exit v0

    .line 44
    return-void

    .line 45
    :catchall_0
    move-exception p0

    .line 46
    goto :goto_0

    .line 47
    :catchall_1
    move-exception v1

    .line 48
    iget-object p0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 51
    .line 52
    .line 53
    throw v1

    .line 54
    :goto_0
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 55
    throw p0

    .line 56
    :pswitch_0
    iget-object v0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 57
    .line 58
    monitor-enter v0

    .line 59
    :try_start_2
    iget-object v1, p0, Lvp/d2;->f:Lvp/j2;

    .line 60
    .line 61
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v1, Lvp/g1;

    .line 64
    .line 65
    iget-object v2, v1, Lvp/g1;->g:Lvp/h;

    .line 66
    .line 67
    invoke-virtual {v1}, Lvp/g1;->q()Lvp/h0;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-virtual {v1}, Lvp/h0;->g0()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    sget-object v3, Lvp/z;->b0:Lvp/y;

    .line 76
    .line 77
    invoke-virtual {v2, v1, v3}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 82
    .line 83
    .line 84
    :try_start_3
    iget-object p0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 87
    .line 88
    .line 89
    monitor-exit v0

    .line 90
    return-void

    .line 91
    :catchall_2
    move-exception p0

    .line 92
    goto :goto_1

    .line 93
    :catchall_3
    move-exception v1

    .line 94
    iget-object p0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 95
    .line 96
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 97
    .line 98
    .line 99
    throw v1

    .line 100
    :goto_1
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 101
    throw p0

    .line 102
    :pswitch_1
    iget-object v0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 103
    .line 104
    monitor-enter v0

    .line 105
    :try_start_4
    iget-object v1, p0, Lvp/d2;->f:Lvp/j2;

    .line 106
    .line 107
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v1, Lvp/g1;

    .line 110
    .line 111
    iget-object v2, v1, Lvp/g1;->g:Lvp/h;

    .line 112
    .line 113
    invoke-virtual {v1}, Lvp/g1;->q()Lvp/h0;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    invoke-virtual {v1}, Lvp/h0;->g0()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    sget-object v3, Lvp/z;->a0:Lvp/y;

    .line 122
    .line 123
    invoke-virtual {v2, v1, v3}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    .line 132
    .line 133
    .line 134
    :try_start_5
    iget-object p0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 135
    .line 136
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 137
    .line 138
    .line 139
    monitor-exit v0

    .line 140
    return-void

    .line 141
    :catchall_4
    move-exception p0

    .line 142
    goto :goto_2

    .line 143
    :catchall_5
    move-exception v1

    .line 144
    iget-object p0, p0, Lvp/d2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 145
    .line 146
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 147
    .line 148
    .line 149
    throw v1

    .line 150
    :goto_2
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 151
    throw p0

    .line 152
    nop

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
