.class public final Lh01/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final d:Ld01/k;

.field public volatile e:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final synthetic f:Lh01/o;


# direct methods
.method public constructor <init>(Lh01/o;Ld01/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh01/l;->f:Lh01/o;

    .line 5
    .line 6
    iput-object p2, p0, Lh01/l;->d:Ld01/k;

    .line 7
    .line 8
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 9
    .line 10
    const/4 p2, 0x0

    .line 11
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lh01/l;->e:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 10

    .line 1
    const-string v0, "Callback failure for "

    .line 2
    .line 3
    const-string v1, "canceled due to "

    .line 4
    .line 5
    new-instance v2, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v3, "OkHttp "

    .line 8
    .line 9
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v3, p0, Lh01/l;->f:Lh01/o;

    .line 13
    .line 14
    iget-object v3, v3, Lh01/o;->e:Ld01/k0;

    .line 15
    .line 16
    iget-object v3, v3, Ld01/k0;->a:Ld01/a0;

    .line 17
    .line 18
    invoke-virtual {v3}, Ld01/a0;->i()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    iget-object v3, p0, Lh01/l;->f:Lh01/o;

    .line 30
    .line 31
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    invoke-virtual {v4}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-virtual {v4, v2}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :try_start_0
    iget-object v2, v3, Lh01/o;->h:Lh01/n;

    .line 43
    .line 44
    invoke-virtual {v2}, Lu01/d;->h()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    const/4 v2, 0x3

    .line 48
    const/4 v6, 0x0

    .line 49
    const/4 v7, 0x0

    .line 50
    :try_start_1
    invoke-virtual {v3}, Lh01/o;->e()Ld01/t0;

    .line 51
    .line 52
    .line 53
    move-result-object v7
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 54
    const/4 v8, 0x1

    .line 55
    :try_start_2
    iget-object v9, p0, Lh01/l;->d:Ld01/k;

    .line 56
    .line 57
    invoke-interface {v9, v3, v7}, Ld01/k;->onResponse(Ld01/j;Ld01/t0;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 58
    .line 59
    .line 60
    :try_start_3
    iget-object v0, v3, Lh01/o;->d:Ld01/h0;

    .line 61
    .line 62
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;

    .line 63
    .line 64
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-static {v0, v6, v6, p0, v2}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 68
    .line 69
    .line 70
    goto :goto_5

    .line 71
    :catchall_0
    move-exception p0

    .line 72
    goto/16 :goto_7

    .line 73
    .line 74
    :catchall_1
    move-exception v0

    .line 75
    move v7, v8

    .line 76
    goto :goto_1

    .line 77
    :catch_0
    move-exception v1

    .line 78
    move v7, v8

    .line 79
    goto :goto_3

    .line 80
    :catchall_2
    move-exception v0

    .line 81
    :goto_1
    :try_start_4
    invoke-virtual {v3}, Lh01/o;->cancel()V

    .line 82
    .line 83
    .line 84
    if-nez v7, :cond_0

    .line 85
    .line 86
    new-instance v7, Ljava/io/IOException;

    .line 87
    .line 88
    new-instance v8, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    invoke-direct {v8, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    invoke-direct {v7, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v7, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 104
    .line 105
    .line 106
    iget-object v1, p0, Lh01/l;->d:Ld01/k;

    .line 107
    .line 108
    invoke-interface {v1, v3, v7}, Ld01/k;->onFailure(Ld01/j;Ljava/io/IOException;)V

    .line 109
    .line 110
    .line 111
    goto :goto_2

    .line 112
    :catchall_3
    move-exception v0

    .line 113
    goto :goto_6

    .line 114
    :cond_0
    :goto_2
    instance-of v1, v0, Ljava/lang/InterruptedException;

    .line 115
    .line 116
    if-eqz v1, :cond_1

    .line 117
    .line 118
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 123
    .line 124
    .line 125
    :try_start_5
    iget-object v0, v3, Lh01/o;->d:Ld01/h0;

    .line 126
    .line 127
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 128
    .line 129
    goto :goto_0

    .line 130
    :cond_1
    :try_start_6
    throw v0

    .line 131
    :catch_1
    move-exception v1

    .line 132
    :goto_3
    if-eqz v7, :cond_2

    .line 133
    .line 134
    sget-object v7, Ln01/d;->a:Ln01/b;

    .line 135
    .line 136
    sget-object v7, Ln01/d;->a:Ln01/b;

    .line 137
    .line 138
    new-instance v8, Ljava/lang/StringBuilder;

    .line 139
    .line 140
    invoke-direct {v8, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    invoke-static {v3}, Lh01/o;->a(Lh01/o;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    const/4 v8, 0x4

    .line 155
    invoke-virtual {v7, v8, v0, v1}, Ln01/b;->c(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 156
    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_2
    iget-object v0, p0, Lh01/l;->d:Ld01/k;

    .line 160
    .line 161
    invoke-interface {v0, v3, v1}, Ld01/k;->onFailure(Ld01/j;Ljava/io/IOException;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 162
    .line 163
    .line 164
    :goto_4
    :try_start_7
    iget-object v0, v3, Lh01/o;->d:Ld01/h0;

    .line 165
    .line 166
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 167
    .line 168
    goto :goto_0

    .line 169
    :goto_5
    invoke-virtual {v4, v5}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    return-void

    .line 173
    :goto_6
    :try_start_8
    iget-object v1, v3, Lh01/o;->d:Ld01/h0;

    .line 174
    .line 175
    iget-object v1, v1, Ld01/h0;->a:Ld01/t;

    .line 176
    .line 177
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 178
    .line 179
    .line 180
    invoke-static {v1, v6, v6, p0, v2}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V

    .line 181
    .line 182
    .line 183
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 184
    :goto_7
    invoke-virtual {v4, v5}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    throw p0
.end method
