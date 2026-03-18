.class public final Lf8/e;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lf8/e;->a:I

    invoke-direct {p0}, Landroid/os/Handler;-><init>()V

    return-void
.end method

.method public constructor <init>(Lf8/g;Landroid/os/Looper;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lf8/e;->a:I

    .line 2
    iput-object p1, p0, Lf8/e;->b:Ljava/lang/Object;

    invoke-direct {p0, p2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)V
    .locals 10

    .line 1
    iget v0, p0, Lf8/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p1, Landroid/os/Message;->what:I

    .line 7
    .line 8
    const/4 v1, -0x3

    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    const/4 v1, -0x2

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    const/4 v1, -0x1

    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    if-eq v0, p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroid/content/DialogInterface;

    .line 24
    .line 25
    invoke-interface {p0}, Landroid/content/DialogInterface;->dismiss()V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    iget-object v0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Landroid/content/DialogInterface$OnClickListener;

    .line 32
    .line 33
    iget-object p0, p0, Lf8/e;->b:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Ljava/lang/ref/WeakReference;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Landroid/content/DialogInterface;

    .line 42
    .line 43
    iget p1, p1, Landroid/os/Message;->what:I

    .line 44
    .line 45
    invoke-interface {v0, p0, p1}, Landroid/content/DialogInterface$OnClickListener;->onClick(Landroid/content/DialogInterface;I)V

    .line 46
    .line 47
    .line 48
    :goto_0
    return-void

    .line 49
    :pswitch_0
    iget-object p0, p0, Lf8/e;->b:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lf8/g;

    .line 52
    .line 53
    iget v0, p1, Landroid/os/Message;->what:I

    .line 54
    .line 55
    const/4 v1, 0x1

    .line 56
    const/4 v2, 0x0

    .line 57
    if-eq v0, v1, :cond_b

    .line 58
    .line 59
    const/4 v1, 0x2

    .line 60
    if-eq v0, v1, :cond_8

    .line 61
    .line 62
    const/4 v1, 0x3

    .line 63
    if-eq v0, v1, :cond_7

    .line 64
    .line 65
    const/4 v1, 0x4

    .line 66
    if-eq v0, v1, :cond_4

    .line 67
    .line 68
    iget-object v0, p0, Lf8/g;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 69
    .line 70
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    iget p0, p1, Landroid/os/Message;->what:I

    .line 73
    .line 74
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    :cond_2
    invoke-virtual {v0, v2, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    if-eqz p0, :cond_3

    .line 86
    .line 87
    goto/16 :goto_3

    .line 88
    .line 89
    :cond_3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-eqz p0, :cond_2

    .line 94
    .line 95
    goto/16 :goto_3

    .line 96
    .line 97
    :cond_4
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p1, Landroid/os/Bundle;

    .line 100
    .line 101
    :try_start_0
    iget-object v0, p0, Lf8/g;->a:Landroid/media/MediaCodec;

    .line 102
    .line 103
    invoke-virtual {v0, p1}, Landroid/media/MediaCodec;->setParameters(Landroid/os/Bundle;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 104
    .line 105
    .line 106
    goto/16 :goto_3

    .line 107
    .line 108
    :catch_0
    move-exception v0

    .line 109
    move-object p1, v0

    .line 110
    iget-object v0, p0, Lf8/g;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 111
    .line 112
    :cond_5
    invoke-virtual {v0, v2, p1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-eqz p0, :cond_6

    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    if-eqz p0, :cond_5

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_7
    iget-object p0, p0, Lf8/g;->e:Lw7/e;

    .line 127
    .line 128
    invoke-virtual {p0}, Lw7/e;->c()Z

    .line 129
    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_8
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v1, p1

    .line 135
    check-cast v1, Lf8/f;

    .line 136
    .line 137
    iget v4, v1, Lf8/f;->a:I

    .line 138
    .line 139
    iget-object v6, v1, Lf8/f;->c:Landroid/media/MediaCodec$CryptoInfo;

    .line 140
    .line 141
    iget-wide v7, v1, Lf8/f;->d:J

    .line 142
    .line 143
    iget v9, v1, Lf8/f;->e:I

    .line 144
    .line 145
    :try_start_1
    sget-object p1, Lf8/g;->h:Ljava/lang/Object;

    .line 146
    .line 147
    monitor-enter p1
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 148
    :try_start_2
    iget-object v3, p0, Lf8/g;->a:Landroid/media/MediaCodec;

    .line 149
    .line 150
    const/4 v5, 0x0

    .line 151
    invoke-virtual/range {v3 .. v9}, Landroid/media/MediaCodec;->queueSecureInputBuffer(IILandroid/media/MediaCodec$CryptoInfo;JI)V

    .line 152
    .line 153
    .line 154
    monitor-exit p1

    .line 155
    goto :goto_1

    .line 156
    :catchall_0
    move-exception v0

    .line 157
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 158
    :try_start_3
    throw v0
    :try_end_3
    .catch Ljava/lang/RuntimeException; {:try_start_3 .. :try_end_3} :catch_1

    .line 159
    :catch_1
    move-exception v0

    .line 160
    move-object p1, v0

    .line 161
    iget-object v3, p0, Lf8/g;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 162
    .line 163
    :cond_9
    invoke-virtual {v3, v2, v0}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result p0

    .line 167
    if-eqz p0, :cond_a

    .line 168
    .line 169
    goto :goto_1

    .line 170
    :cond_a
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    if-eqz p0, :cond_9

    .line 175
    .line 176
    :goto_1
    move-object v2, v1

    .line 177
    goto :goto_3

    .line 178
    :cond_b
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast p1, Lf8/f;

    .line 181
    .line 182
    iget v4, p1, Lf8/f;->a:I

    .line 183
    .line 184
    iget v6, p1, Lf8/f;->b:I

    .line 185
    .line 186
    iget-wide v7, p1, Lf8/f;->d:J

    .line 187
    .line 188
    iget v9, p1, Lf8/f;->e:I

    .line 189
    .line 190
    :try_start_4
    iget-object v3, p0, Lf8/g;->a:Landroid/media/MediaCodec;

    .line 191
    .line 192
    const/4 v5, 0x0

    .line 193
    invoke-virtual/range {v3 .. v9}, Landroid/media/MediaCodec;->queueInputBuffer(IIIJI)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_2

    .line 194
    .line 195
    .line 196
    goto :goto_2

    .line 197
    :catch_2
    move-exception v0

    .line 198
    iget-object p0, p0, Lf8/g;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 199
    .line 200
    :cond_c
    invoke-virtual {p0, v2, v0}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v1

    .line 204
    if-eqz v1, :cond_d

    .line 205
    .line 206
    goto :goto_2

    .line 207
    :cond_d
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    if-eqz v1, :cond_c

    .line 212
    .line 213
    :goto_2
    move-object v2, p1

    .line 214
    :goto_3
    if-eqz v2, :cond_e

    .line 215
    .line 216
    sget-object p0, Lf8/g;->g:Ljava/util/ArrayDeque;

    .line 217
    .line 218
    monitor-enter p0

    .line 219
    :try_start_5
    invoke-virtual {p0, v2}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    monitor-exit p0

    .line 223
    goto :goto_4

    .line 224
    :catchall_1
    move-exception v0

    .line 225
    move-object p1, v0

    .line 226
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 227
    throw p1

    .line 228
    :cond_e
    :goto_4
    return-void

    .line 229
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
