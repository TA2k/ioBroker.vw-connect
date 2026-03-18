.class public final Lvp/f2;
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

    iput p3, p0, Lvp/f2;->d:I

    packed-switch p3, :pswitch_data_0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/f2;->f:Lvp/j2;

    return-void

    .line 3
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/f2;->f:Lvp/j2;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public synthetic constructor <init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;IZ)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/f2;->d:I

    iput-object p1, p0, Lvp/f2;->f:Lvp/j2;

    iput-object p2, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    .line 1
    iget v0, p0, Lvp/f2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/f2;->f:Lvp/j2;

    .line 7
    .line 8
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lvp/g1;

    .line 11
    .line 12
    invoke-virtual {v0}, Lvp/g1;->o()Lvp/d3;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    sget-object v0, Lvp/q2;->h:Lvp/q2;

    .line 17
    .line 18
    filled-new-array {v0}, [Lvp/q2;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lvp/s3;->x0([Lvp/q2;)Lvp/s3;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    iget-object v3, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 27
    .line 28
    invoke-virtual {v2}, Lvp/x;->a0()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2}, Lvp/b0;->b0()V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    invoke-virtual {v2, p0}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    new-instance v1, Ld6/z0;

    .line 40
    .line 41
    const/16 v6, 0xb

    .line 42
    .line 43
    invoke-direct/range {v1 .. v6}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v2, v1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :pswitch_0
    iget-object v0, p0, Lvp/f2;->f:Lvp/j2;

    .line 51
    .line 52
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v1, Lvp/g1;

    .line 55
    .line 56
    iget-object v1, v1, Lvp/g1;->h:Lvp/w0;

    .line 57
    .line 58
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, v1, Lvp/w0;->r:Lun/a;

    .line 62
    .line 63
    invoke-virtual {v1}, Lun/a;->b()Landroid/os/Bundle;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Lvp/g1;

    .line 70
    .line 71
    invoke-virtual {v0}, Lvp/g1;->o()Lvp/d3;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    iget-object v4, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 76
    .line 77
    invoke-virtual {v3}, Lvp/x;->a0()V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v3}, Lvp/b0;->b0()V

    .line 81
    .line 82
    .line 83
    const/4 p0, 0x0

    .line 84
    invoke-virtual {v3, p0}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    new-instance v2, Ld6/z0;

    .line 89
    .line 90
    const/16 v7, 0xa

    .line 91
    .line 92
    invoke-direct/range {v2 .. v7}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3, v2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :pswitch_1
    iget-object v1, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 100
    .line 101
    monitor-enter v1

    .line 102
    :try_start_0
    iget-object v0, p0, Lvp/f2;->f:Lvp/j2;

    .line 103
    .line 104
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v0, Lvp/g1;

    .line 107
    .line 108
    iget-object v2, v0, Lvp/g1;->g:Lvp/h;

    .line 109
    .line 110
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    invoke-virtual {v0}, Lvp/h0;->g0()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    sget-object v3, Lvp/z;->e0:Lvp/y;

    .line 119
    .line 120
    invoke-virtual {v2, v0, v3}, Lvp/h;->j0(Ljava/lang/String;Lvp/y;)D

    .line 121
    .line 122
    .line 123
    move-result-wide v2

    .line 124
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 129
    .line 130
    .line 131
    :try_start_1
    iget-object p0, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 132
    .line 133
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 134
    .line 135
    .line 136
    monitor-exit v1

    .line 137
    return-void

    .line 138
    :catchall_0
    move-exception v0

    .line 139
    move-object p0, v0

    .line 140
    goto :goto_0

    .line 141
    :catchall_1
    move-exception v0

    .line 142
    iget-object p0, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 143
    .line 144
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 145
    .line 146
    .line 147
    throw v0

    .line 148
    :goto_0
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 149
    throw p0

    .line 150
    :pswitch_2
    iget-object v1, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 151
    .line 152
    monitor-enter v1

    .line 153
    :try_start_2
    iget-object v0, p0, Lvp/f2;->f:Lvp/j2;

    .line 154
    .line 155
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Lvp/g1;

    .line 158
    .line 159
    iget-object v2, v0, Lvp/g1;->g:Lvp/h;

    .line 160
    .line 161
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-virtual {v0}, Lvp/h0;->g0()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    sget-object v3, Lvp/z;->c0:Lvp/y;

    .line 170
    .line 171
    invoke-virtual {v2, v0, v3}, Lvp/h;->h0(Ljava/lang/String;Lvp/y;)J

    .line 172
    .line 173
    .line 174
    move-result-wide v2

    .line 175
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 180
    .line 181
    .line 182
    :try_start_3
    iget-object p0, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 183
    .line 184
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 185
    .line 186
    .line 187
    monitor-exit v1

    .line 188
    return-void

    .line 189
    :catchall_2
    move-exception v0

    .line 190
    move-object p0, v0

    .line 191
    goto :goto_1

    .line 192
    :catchall_3
    move-exception v0

    .line 193
    iget-object p0, p0, Lvp/f2;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 194
    .line 195
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 196
    .line 197
    .line 198
    throw v0

    .line 199
    :goto_1
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 200
    throw p0

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
