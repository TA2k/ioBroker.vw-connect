.class public final Lf8/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf8/n;


# static fields
.field public static final g:Ljava/util/ArrayDeque;

.field public static final h:Ljava/lang/Object;


# instance fields
.field public final a:Landroid/media/MediaCodec;

.field public final b:Landroid/os/HandlerThread;

.field public c:Lf8/e;

.field public final d:Ljava/util/concurrent/atomic/AtomicReference;

.field public final e:Lw7/e;

.field public f:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lf8/g;->g:Ljava/util/ArrayDeque;

    .line 7
    .line 8
    new-instance v0, Ljava/lang/Object;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lf8/g;->h:Ljava/lang/Object;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Landroid/media/MediaCodec;Landroid/os/HandlerThread;)V
    .locals 1

    .line 1
    new-instance v0, Lw7/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lw7/e;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lf8/g;->a:Landroid/media/MediaCodec;

    .line 10
    .line 11
    iput-object p2, p0, Lf8/g;->b:Landroid/os/HandlerThread;

    .line 12
    .line 13
    iput-object v0, p0, Lf8/g;->e:Lw7/e;

    .line 14
    .line 15
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 16
    .line 17
    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lf8/g;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 21
    .line 22
    return-void
.end method

.method public static c()Lf8/f;
    .locals 2

    .line 1
    sget-object v0, Lf8/g;->g:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    new-instance v1, Lf8/f;

    .line 11
    .line 12
    invoke-direct {v1}, Lf8/f;-><init>()V

    .line 13
    .line 14
    .line 15
    monitor-exit v0

    .line 16
    return-object v1

    .line 17
    :catchall_0
    move-exception v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    check-cast v1, Lf8/f;

    .line 24
    .line 25
    monitor-exit v0

    .line 26
    return-object v1

    .line 27
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    throw v1
.end method


# virtual methods
.method public final a(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lf8/g;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lf8/g;->c:Lf8/e;

    .line 5
    .line 6
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    invoke-virtual {p0, v0, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object p0, p0, Lf8/g;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Ljava/lang/RuntimeException;

    .line 9
    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    throw p0
.end method

.method public final d(JIII)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lf8/g;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lf8/g;->c()Lf8/f;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput p3, v0, Lf8/f;->a:I

    .line 9
    .line 10
    iput p4, v0, Lf8/f;->b:I

    .line 11
    .line 12
    iput-wide p1, v0, Lf8/f;->d:J

    .line 13
    .line 14
    iput p5, v0, Lf8/f;->e:I

    .line 15
    .line 16
    iget-object p0, p0, Lf8/g;->c:Lf8/e;

    .line 17
    .line 18
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    invoke-virtual {p0, p1, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final e(ILz7/b;JI)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lf8/g;->b()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lf8/g;->c()Lf8/f;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput p1, v0, Lf8/f;->a:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    iput p1, v0, Lf8/f;->b:I

    .line 12
    .line 13
    iput-wide p3, v0, Lf8/f;->d:J

    .line 14
    .line 15
    iput p5, v0, Lf8/f;->e:I

    .line 16
    .line 17
    iget-object p3, v0, Lf8/f;->c:Landroid/media/MediaCodec$CryptoInfo;

    .line 18
    .line 19
    iget p4, p2, Lz7/b;->f:I

    .line 20
    .line 21
    iput p4, p3, Landroid/media/MediaCodec$CryptoInfo;->numSubSamples:I

    .line 22
    .line 23
    iget-object p4, p2, Lz7/b;->d:[I

    .line 24
    .line 25
    iget-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->numBytesOfClearData:[I

    .line 26
    .line 27
    if-nez p4, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    if-eqz p5, :cond_2

    .line 31
    .line 32
    array-length v1, p5

    .line 33
    array-length v2, p4

    .line 34
    if-ge v1, v2, :cond_1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    array-length v1, p4

    .line 38
    invoke-static {p4, p1, p5, p1, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    :goto_0
    array-length p5, p4

    .line 43
    invoke-static {p4, p5}, Ljava/util/Arrays;->copyOf([II)[I

    .line 44
    .line 45
    .line 46
    move-result-object p5

    .line 47
    :goto_1
    iput-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->numBytesOfClearData:[I

    .line 48
    .line 49
    iget-object p4, p2, Lz7/b;->e:[I

    .line 50
    .line 51
    iget-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->numBytesOfEncryptedData:[I

    .line 52
    .line 53
    if-nez p4, :cond_3

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_3
    if-eqz p5, :cond_5

    .line 57
    .line 58
    array-length v1, p5

    .line 59
    array-length v2, p4

    .line 60
    if-ge v1, v2, :cond_4

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_4
    array-length v1, p4

    .line 64
    invoke-static {p4, p1, p5, p1, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 65
    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_5
    :goto_2
    array-length p5, p4

    .line 69
    invoke-static {p4, p5}, Ljava/util/Arrays;->copyOf([II)[I

    .line 70
    .line 71
    .line 72
    move-result-object p5

    .line 73
    :goto_3
    iput-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->numBytesOfEncryptedData:[I

    .line 74
    .line 75
    iget-object p4, p2, Lz7/b;->b:[B

    .line 76
    .line 77
    iget-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->key:[B

    .line 78
    .line 79
    if-nez p4, :cond_6

    .line 80
    .line 81
    goto :goto_5

    .line 82
    :cond_6
    if-eqz p5, :cond_8

    .line 83
    .line 84
    array-length v1, p5

    .line 85
    array-length v2, p4

    .line 86
    if-ge v1, v2, :cond_7

    .line 87
    .line 88
    goto :goto_4

    .line 89
    :cond_7
    array-length v1, p4

    .line 90
    invoke-static {p4, p1, p5, p1, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 91
    .line 92
    .line 93
    goto :goto_5

    .line 94
    :cond_8
    :goto_4
    array-length p5, p4

    .line 95
    invoke-static {p4, p5}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 96
    .line 97
    .line 98
    move-result-object p5

    .line 99
    :goto_5
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    iput-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->key:[B

    .line 103
    .line 104
    iget-object p4, p2, Lz7/b;->a:[B

    .line 105
    .line 106
    iget-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->iv:[B

    .line 107
    .line 108
    if-nez p4, :cond_9

    .line 109
    .line 110
    goto :goto_7

    .line 111
    :cond_9
    if-eqz p5, :cond_b

    .line 112
    .line 113
    array-length v1, p5

    .line 114
    array-length v2, p4

    .line 115
    if-ge v1, v2, :cond_a

    .line 116
    .line 117
    goto :goto_6

    .line 118
    :cond_a
    array-length v1, p4

    .line 119
    invoke-static {p4, p1, p5, p1, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 120
    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_b
    :goto_6
    array-length p1, p4

    .line 124
    invoke-static {p4, p1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 125
    .line 126
    .line 127
    move-result-object p5

    .line 128
    :goto_7
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    iput-object p5, p3, Landroid/media/MediaCodec$CryptoInfo;->iv:[B

    .line 132
    .line 133
    iget p1, p2, Lz7/b;->c:I

    .line 134
    .line 135
    iput p1, p3, Landroid/media/MediaCodec$CryptoInfo;->mode:I

    .line 136
    .line 137
    new-instance p1, Landroid/media/MediaCodec$CryptoInfo$Pattern;

    .line 138
    .line 139
    iget p4, p2, Lz7/b;->g:I

    .line 140
    .line 141
    iget p2, p2, Lz7/b;->h:I

    .line 142
    .line 143
    invoke-direct {p1, p4, p2}, Landroid/media/MediaCodec$CryptoInfo$Pattern;-><init>(II)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p3, p1}, Landroid/media/MediaCodec$CryptoInfo;->setPattern(Landroid/media/MediaCodec$CryptoInfo$Pattern;)V

    .line 147
    .line 148
    .line 149
    iget-object p0, p0, Lf8/g;->c:Lf8/e;

    .line 150
    .line 151
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 152
    .line 153
    const/4 p1, 0x2

    .line 154
    invoke-virtual {p0, p1, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 159
    .line 160
    .line 161
    return-void
.end method

.method public final flush()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lf8/g;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    :try_start_0
    iget-object v0, p0, Lf8/g;->c:Lf8/e;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lf8/g;->e:Lw7/e;

    .line 15
    .line 16
    monitor-enter v0
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    const/4 v1, 0x0

    .line 18
    :try_start_1
    iput-boolean v1, v0, Lw7/e;->b:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 19
    .line 20
    :try_start_2
    monitor-exit v0

    .line 21
    iget-object p0, p0, Lf8/g;->c:Lf8/e;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    const/4 v1, 0x3

    .line 27
    invoke-virtual {p0, v1}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0}, Landroid/os/Message;->sendToTarget()V

    .line 32
    .line 33
    .line 34
    monitor-enter v0
    :try_end_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_0

    .line 35
    :goto_0
    :try_start_3
    iget-boolean p0, v0, Lw7/e;->b:Z

    .line 36
    .line 37
    if-nez p0, :cond_0

    .line 38
    .line 39
    iget-object p0, v0, Lw7/e;->a:Lw7/r;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Object;->wait()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :catchall_0
    move-exception p0

    .line 49
    goto :goto_1

    .line 50
    :cond_0
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catch Ljava/lang/InterruptedException; {:try_start_4 .. :try_end_4} :catch_0

    .line 51
    return-void

    .line 52
    :goto_1
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 53
    :try_start_6
    throw p0
    :try_end_6
    .catch Ljava/lang/InterruptedException; {:try_start_6 .. :try_end_6} :catch_0

    .line 54
    :catchall_1
    move-exception p0

    .line 55
    :try_start_7
    monitor-exit v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 56
    :try_start_8
    throw p0
    :try_end_8
    .catch Ljava/lang/InterruptedException; {:try_start_8 .. :try_end_8} :catch_0

    .line 57
    :catch_0
    move-exception p0

    .line 58
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V

    .line 63
    .line 64
    .line 65
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_1
    return-void
.end method

.method public final shutdown()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lf8/g;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lf8/g;->flush()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lf8/g;->b:Landroid/os/HandlerThread;

    .line 9
    .line 10
    invoke-virtual {v0}, Landroid/os/HandlerThread;->quit()Z

    .line 11
    .line 12
    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    iput-boolean v0, p0, Lf8/g;->f:Z

    .line 15
    .line 16
    return-void
.end method

.method public final start()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lf8/g;->f:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lf8/g;->b:Landroid/os/HandlerThread;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 8
    .line 9
    .line 10
    new-instance v1, Lf8/e;

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-direct {v1, p0, v0}, Lf8/e;-><init>(Lf8/g;Landroid/os/Looper;)V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lf8/g;->c:Lf8/e;

    .line 20
    .line 21
    const/4 v0, 0x1

    .line 22
    iput-boolean v0, p0, Lf8/g;->f:Z

    .line 23
    .line 24
    :cond_0
    return-void
.end method
