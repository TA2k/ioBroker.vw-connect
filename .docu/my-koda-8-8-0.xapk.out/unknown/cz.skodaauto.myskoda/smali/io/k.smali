.class public final synthetic Lio/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lio/m;


# direct methods
.method public synthetic constructor <init>(Lio/m;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/k;->e:Lio/m;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    .line 1
    iget v0, p0, Lio/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "Service disconnected"

    .line 7
    .line 8
    iget-object p0, p0, Lio/k;->e:Lio/m;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lio/m;->a(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Lio/k;->e:Lio/m;

    .line 15
    .line 16
    monitor-enter v0

    .line 17
    :try_start_0
    iget p0, v0, Lio/m;->a:I

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    if-ne p0, v1, :cond_0

    .line 21
    .line 22
    const-string p0, "Timed out while binding"

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lio/m;->a(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    .line 27
    :cond_0
    monitor-exit v0

    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    goto :goto_1

    .line 31
    :goto_0
    return-void

    .line 32
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    throw p0

    .line 34
    :goto_2
    :pswitch_1
    iget-object v0, p0, Lio/k;->e:Lio/m;

    .line 35
    .line 36
    monitor-enter v0

    .line 37
    :try_start_2
    iget v1, v0, Lio/m;->a:I

    .line 38
    .line 39
    const/4 v2, 0x2

    .line 40
    if-eq v1, v2, :cond_1

    .line 41
    .line 42
    monitor-exit v0

    .line 43
    goto :goto_3

    .line 44
    :catchall_1
    move-exception p0

    .line 45
    goto/16 :goto_4

    .line 46
    .line 47
    :cond_1
    iget-object v1, v0, Lio/m;->d:Ljava/util/ArrayDeque;

    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_2

    .line 54
    .line 55
    invoke-virtual {v0}, Lio/m;->c()V

    .line 56
    .line 57
    .line 58
    monitor-exit v0

    .line 59
    :goto_3
    return-void

    .line 60
    :cond_2
    iget-object v1, v0, Lio/m;->d:Ljava/util/ArrayDeque;

    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    check-cast v1, Lio/n;

    .line 67
    .line 68
    iget-object v2, v0, Lio/m;->e:Landroid/util/SparseArray;

    .line 69
    .line 70
    iget v3, v1, Lio/n;->a:I

    .line 71
    .line 72
    invoke-virtual {v2, v3, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v2, v0, Lio/m;->f:Lio/o;

    .line 76
    .line 77
    iget-object v2, v2, Lio/o;->f:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v2, Ljava/util/concurrent/ScheduledExecutorService;

    .line 80
    .line 81
    new-instance v3, Llr/b;

    .line 82
    .line 83
    const/16 v4, 0x9

    .line 84
    .line 85
    invoke-direct {v3, v4, v0, v1}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    sget-object v4, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 89
    .line 90
    const-wide/16 v5, 0x1e

    .line 91
    .line 92
    invoke-interface {v2, v3, v5, v6, v4}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 93
    .line 94
    .line 95
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 96
    const-string v2, "MessengerIpcClient"

    .line 97
    .line 98
    const/4 v3, 0x3

    .line 99
    invoke-static {v2, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    if-eqz v2, :cond_3

    .line 104
    .line 105
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    const-string v3, "Sending "

    .line 110
    .line 111
    const-string v4, "MessengerIpcClient"

    .line 112
    .line 113
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    invoke-static {v4, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 118
    .line 119
    .line 120
    :cond_3
    iget-object v2, v0, Lio/m;->f:Lio/o;

    .line 121
    .line 122
    iget-object v3, v0, Lio/m;->b:Landroid/os/Messenger;

    .line 123
    .line 124
    iget v4, v1, Lio/n;->c:I

    .line 125
    .line 126
    iget-object v2, v2, Lio/o;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v2, Landroid/content/Context;

    .line 129
    .line 130
    invoke-static {}, Landroid/os/Message;->obtain()Landroid/os/Message;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    iput v4, v5, Landroid/os/Message;->what:I

    .line 135
    .line 136
    iget v4, v1, Lio/n;->a:I

    .line 137
    .line 138
    iput v4, v5, Landroid/os/Message;->arg1:I

    .line 139
    .line 140
    iput-object v3, v5, Landroid/os/Message;->replyTo:Landroid/os/Messenger;

    .line 141
    .line 142
    new-instance v3, Landroid/os/Bundle;

    .line 143
    .line 144
    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v1}, Lio/n;->a()Z

    .line 148
    .line 149
    .line 150
    move-result v4

    .line 151
    const-string v6, "oneWay"

    .line 152
    .line 153
    invoke-virtual {v3, v6, v4}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    const-string v4, "pkg"

    .line 161
    .line 162
    invoke-virtual {v3, v4, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    iget-object v1, v1, Lio/n;->d:Landroid/os/Bundle;

    .line 166
    .line 167
    const-string v2, "data"

    .line 168
    .line 169
    invoke-virtual {v3, v2, v1}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v5, v3}, Landroid/os/Message;->setData(Landroid/os/Bundle;)V

    .line 173
    .line 174
    .line 175
    :try_start_3
    iget-object v1, v0, Lio/m;->c:Lc2/k;

    .line 176
    .line 177
    iget-object v2, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v2, Landroid/os/Messenger;

    .line 180
    .line 181
    if-eqz v2, :cond_4

    .line 182
    .line 183
    invoke-virtual {v2, v5}, Landroid/os/Messenger;->send(Landroid/os/Message;)V

    .line 184
    .line 185
    .line 186
    goto/16 :goto_2

    .line 187
    .line 188
    :cond_4
    iget-object v1, v1, Lc2/k;->f:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v1, Lio/g;

    .line 191
    .line 192
    if-eqz v1, :cond_5

    .line 193
    .line 194
    iget-object v1, v1, Lio/g;->d:Landroid/os/Messenger;

    .line 195
    .line 196
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    invoke-virtual {v1, v5}, Landroid/os/Messenger;->send(Landroid/os/Message;)V

    .line 200
    .line 201
    .line 202
    goto/16 :goto_2

    .line 203
    .line 204
    :cond_5
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 205
    .line 206
    const-string v2, "Both messengers are null"

    .line 207
    .line 208
    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    throw v1
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_0

    .line 212
    :catch_0
    move-exception v1

    .line 213
    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    invoke-virtual {v0, v1}, Lio/m;->a(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    goto/16 :goto_2

    .line 221
    .line 222
    :goto_4
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 223
    throw p0

    .line 224
    nop

    .line 225
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
