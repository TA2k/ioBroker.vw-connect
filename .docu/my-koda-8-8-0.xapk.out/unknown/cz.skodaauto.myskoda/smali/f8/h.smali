.class public final Lf8/h;
.super Landroid/media/MediaCodec$Callback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Landroid/os/HandlerThread;

.field public c:Landroid/os/Handler;

.field public final d:Landroidx/collection/i;

.field public final e:Landroidx/collection/i;

.field public final f:Ljava/util/ArrayDeque;

.field public final g:Ljava/util/ArrayDeque;

.field public h:Landroid/media/MediaFormat;

.field public i:Landroid/media/MediaFormat;

.field public j:Landroid/media/MediaCodec$CodecException;

.field public k:Landroid/media/MediaCodec$CryptoException;

.field public l:J

.field public m:Z

.field public n:Ljava/lang/IllegalStateException;

.field public o:Lbu/c;


# direct methods
.method public constructor <init>(Landroid/os/HandlerThread;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/media/MediaCodec$Callback;-><init>()V

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
    iput-object v0, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p1, p0, Lf8/h;->b:Landroid/os/HandlerThread;

    .line 12
    .line 13
    new-instance p1, Landroidx/collection/i;

    .line 14
    .line 15
    invoke-direct {p1}, Landroidx/collection/i;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lf8/h;->d:Landroidx/collection/i;

    .line 19
    .line 20
    new-instance p1, Landroidx/collection/i;

    .line 21
    .line 22
    invoke-direct {p1}, Landroidx/collection/i;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lf8/h;->e:Landroidx/collection/i;

    .line 26
    .line 27
    new-instance p1, Ljava/util/ArrayDeque;

    .line 28
    .line 29
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lf8/h;->f:Ljava/util/ArrayDeque;

    .line 33
    .line 34
    new-instance p1, Ljava/util/ArrayDeque;

    .line 35
    .line 36
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lf8/h;->g:Ljava/util/ArrayDeque;

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    .line 1
    iget-object v0, p0, Lf8/h;->g:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->getLast()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Landroid/media/MediaFormat;

    .line 14
    .line 15
    iput-object v1, p0, Lf8/h;->i:Landroid/media/MediaFormat;

    .line 16
    .line 17
    :cond_0
    iget-object v1, p0, Lf8/h;->d:Landroidx/collection/i;

    .line 18
    .line 19
    iget v2, v1, Landroidx/collection/i;->a:I

    .line 20
    .line 21
    iput v2, v1, Landroidx/collection/i;->b:I

    .line 22
    .line 23
    iget-object v1, p0, Lf8/h;->e:Landroidx/collection/i;

    .line 24
    .line 25
    iget v2, v1, Landroidx/collection/i;->a:I

    .line 26
    .line 27
    iput v2, v1, Landroidx/collection/i;->b:I

    .line 28
    .line 29
    iget-object p0, p0, Lf8/h;->f:Ljava/util/ArrayDeque;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->clear()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->clear()V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final onCryptoError(Landroid/media/MediaCodec;Landroid/media/MediaCodec$CryptoException;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iput-object p2, p0, Lf8/h;->k:Landroid/media/MediaCodec$CryptoException;

    .line 5
    .line 6
    monitor-exit p1

    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public final onError(Landroid/media/MediaCodec;Landroid/media/MediaCodec$CodecException;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iput-object p2, p0, Lf8/h;->j:Landroid/media/MediaCodec$CodecException;

    .line 5
    .line 6
    monitor-exit p1

    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public final onInputBufferAvailable(Landroid/media/MediaCodec;I)V
    .locals 1

    .line 1
    iget-object p1, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object v0, p0, Lf8/h;->d:Landroidx/collection/i;

    .line 5
    .line 6
    invoke-virtual {v0, p2}, Landroidx/collection/i;->a(I)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lf8/h;->o:Lbu/c;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lf8/s;

    .line 16
    .line 17
    iget-object p0, p0, Lf8/s;->J:La8/l0;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, La8/l0;->a()V

    .line 22
    .line 23
    .line 24
    :cond_0
    monitor-exit p1

    .line 25
    return-void

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    throw p0
.end method

.method public final onOutputBufferAvailable(Landroid/media/MediaCodec;ILandroid/media/MediaCodec$BufferInfo;)V
    .locals 3

    .line 1
    iget-object p1, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object v0, p0, Lf8/h;->i:Landroid/media/MediaFormat;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object v1, p0, Lf8/h;->e:Landroidx/collection/i;

    .line 9
    .line 10
    const/4 v2, -0x2

    .line 11
    invoke-virtual {v1, v2}, Landroidx/collection/i;->a(I)V

    .line 12
    .line 13
    .line 14
    iget-object v1, p0, Lf8/h;->g:Ljava/util/ArrayDeque;

    .line 15
    .line 16
    invoke-virtual {v1, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    iput-object v0, p0, Lf8/h;->i:Landroid/media/MediaFormat;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    :goto_0
    iget-object v0, p0, Lf8/h;->e:Landroidx/collection/i;

    .line 26
    .line 27
    invoke-virtual {v0, p2}, Landroidx/collection/i;->a(I)V

    .line 28
    .line 29
    .line 30
    iget-object p2, p0, Lf8/h;->f:Ljava/util/ArrayDeque;

    .line 31
    .line 32
    invoke-virtual {p2, p3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lf8/h;->o:Lbu/c;

    .line 36
    .line 37
    if-eqz p0, :cond_1

    .line 38
    .line 39
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Lf8/s;

    .line 42
    .line 43
    iget-object p0, p0, Lf8/s;->J:La8/l0;

    .line 44
    .line 45
    if-eqz p0, :cond_1

    .line 46
    .line 47
    invoke-virtual {p0}, La8/l0;->a()V

    .line 48
    .line 49
    .line 50
    :cond_1
    monitor-exit p1

    .line 51
    return-void

    .line 52
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    throw p0
.end method

.method public final onOutputFormatChanged(Landroid/media/MediaCodec;Landroid/media/MediaFormat;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object v0, p0, Lf8/h;->e:Landroidx/collection/i;

    .line 5
    .line 6
    const/4 v1, -0x2

    .line 7
    invoke-virtual {v0, v1}, Landroidx/collection/i;->a(I)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lf8/h;->g:Ljava/util/ArrayDeque;

    .line 11
    .line 12
    invoke-virtual {v0, p2}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    iput-object p2, p0, Lf8/h;->i:Landroid/media/MediaFormat;

    .line 17
    .line 18
    monitor-exit p1

    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method
