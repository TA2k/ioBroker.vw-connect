.class public final Lio/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpr/a;


# static fields
.field public static h:Lio/o;

.field public static i:Landroid/os/HandlerThread;

.field public static j:Landroid/os/Handler;


# instance fields
.field public d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    packed-switch p1, :pswitch_data_0

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lio/o;->e:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 16
    iput-object p1, p0, Lio/o;->f:Ljava/lang/Object;

    .line 17
    iput-object p1, p0, Lio/o;->g:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 18
    iput p1, p0, Lio/o;->d:I

    return-void

    .line 19
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 p1, 0x9

    .line 20
    new-array p1, p1, [Landroid/util/SparseIntArray;

    iput-object p1, p0, Lio/o;->e:Ljava/lang/Object;

    .line 21
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lio/o;->f:Ljava/lang/Object;

    .line 22
    new-instance p1, Landroidx/core/app/f;

    invoke-direct {p1, p0}, Landroidx/core/app/f;-><init>(Lio/o;)V

    iput-object p1, p0, Lio/o;->g:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 23
    iput p1, p0, Lio/o;->d:I

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(ILx71/h;)V
    .locals 2

    const-string v0, "pt"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    iput p1, p0, Lio/o;->d:I

    .line 26
    new-instance p1, Lx71/h;

    invoke-direct {p1}, Lx71/h;-><init>()V

    iput-object p1, p0, Lio/o;->e:Ljava/lang/Object;

    .line 27
    iget-wide v0, p2, Lx71/h;->a:J

    .line 28
    iput-wide v0, p1, Lx71/h;->a:J

    .line 29
    iget-wide v0, p2, Lx71/h;->b:J

    .line 30
    iput-wide v0, p1, Lx71/h;->b:J

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljavax/crypto/spec/SecretKeySpec;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lrr/c;

    invoke-direct {v0, p0}, Lrr/c;-><init>(Lio/o;)V

    iput-object v0, p0, Lio/o;->e:Ljava/lang/Object;

    .line 3
    iput-object p1, p0, Lio/o;->f:Ljava/lang/Object;

    .line 4
    iput-object p2, p0, Lio/o;->g:Ljava/lang/Object;

    .line 5
    invoke-virtual {p2}, Ljavax/crypto/spec/SecretKeySpec;->getEncoded()[B

    move-result-object p2

    array-length p2, p2

    const/16 v1, 0x10

    if-lt p2, v1, :cond_4

    .line 6
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    move-result p2

    const/4 v1, -0x1

    sparse-switch p2, :sswitch_data_0

    goto :goto_0

    :sswitch_0
    const-string p2, "HMACSHA512"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x3

    goto :goto_0

    :sswitch_1
    const-string p2, "HMACSHA384"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_1

    goto :goto_0

    :cond_1
    const/4 v1, 0x2

    goto :goto_0

    :sswitch_2
    const-string p2, "HMACSHA256"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_2

    goto :goto_0

    :cond_2
    const/4 v1, 0x1

    goto :goto_0

    :sswitch_3
    const-string p2, "HMACSHA1"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_3

    goto :goto_0

    :cond_3
    const/4 v1, 0x0

    :goto_0
    packed-switch v1, :pswitch_data_0

    .line 7
    new-instance p0, Ljava/security/NoSuchAlgorithmException;

    const-string p2, "unknown Hmac algorithm: "

    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/security/NoSuchAlgorithmException;-><init>(Ljava/lang/String;)V

    throw p0

    :pswitch_0
    const/16 p1, 0x40

    .line 8
    iput p1, p0, Lio/o;->d:I

    goto :goto_1

    :pswitch_1
    const/16 p1, 0x30

    .line 9
    iput p1, p0, Lio/o;->d:I

    goto :goto_1

    :pswitch_2
    const/16 p1, 0x20

    .line 10
    iput p1, p0, Lio/o;->d:I

    goto :goto_1

    :pswitch_3
    const/16 p1, 0x14

    .line 11
    iput p1, p0, Lio/o;->d:I

    .line 12
    :goto_1
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    return-void

    .line 13
    :cond_4
    new-instance p0, Ljava/security/InvalidAlgorithmParameterException;

    const-string p1, "key size too small, need at least 16 bytes"

    invoke-direct {p0, p1}, Ljava/security/InvalidAlgorithmParameterException;-><init>(Ljava/lang/String;)V

    throw p0

    nop

    :sswitch_data_0
    .sparse-switch
        -0x6ca99674 -> :sswitch_3
        0x176240ee -> :sswitch_2
        0x1762450a -> :sswitch_1
        0x17624bb1 -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static declared-synchronized d(Landroid/content/Context;)Lio/o;
    .locals 4

    .line 1
    const-class v0, Lio/o;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lio/o;->h:Lio/o;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lio/o;

    .line 9
    .line 10
    new-instance v2, Luo/a;

    .line 11
    .line 12
    const-string v3, "MessengerIpcClient"

    .line 13
    .line 14
    invoke-direct {v2, v3}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    invoke-static {v3, v2}, Ljava/util/concurrent/Executors;->newScheduledThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ScheduledExecutorService;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-static {v2}, Ljava/util/concurrent/Executors;->unconfigurableScheduledExecutorService(Ljava/util/concurrent/ScheduledExecutorService;)Ljava/util/concurrent/ScheduledExecutorService;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v3, Lio/m;

    .line 30
    .line 31
    invoke-direct {v3, v1}, Lio/m;-><init>(Lio/o;)V

    .line 32
    .line 33
    .line 34
    iput-object v3, v1, Lio/o;->g:Ljava/lang/Object;

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    iput v3, v1, Lio/o;->d:I

    .line 38
    .line 39
    iput-object v2, v1, Lio/o;->f:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    iput-object p0, v1, Lio/o;->e:Ljava/lang/Object;

    .line 46
    .line 47
    sput-object v1, Lio/o;->h:Lio/o;

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    goto :goto_1

    .line 52
    :cond_0
    :goto_0
    sget-object p0, Lio/o;->h:Lio/o;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    .line 54
    monitor-exit v0

    .line 55
    return-object p0

    .line 56
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    throw p0
.end method


# virtual methods
.method public a()Lio/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/o;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lio/o;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const-string p0, "next"

    .line 9
    .line 10
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    throw p0
.end method

.method public b()Lio/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/o;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lio/o;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const-string p0, "prev"

    .line 9
    .line 10
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    throw p0
.end method

.method public c()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lio/o;->d:I

    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    if-lez v1, :cond_0

    .line 8
    .line 9
    move v1, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 v1, 0x0

    .line 12
    :goto_0
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 13
    .line 14
    .line 15
    iget v1, p0, Lio/o;->d:I

    .line 16
    .line 17
    sub-int/2addr v1, v2

    .line 18
    iput v1, p0, Lio/o;->d:I

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    iget-object v1, p0, Lio/o;->g:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Landroid/os/HandlerThread;

    .line 25
    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    invoke-virtual {v1}, Landroid/os/HandlerThread;->quit()Z

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    iput-object v1, p0, Lio/o;->g:Ljava/lang/Object;

    .line 33
    .line 34
    iput-object v1, p0, Lio/o;->f:Ljava/lang/Object;

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    goto :goto_2

    .line 39
    :cond_1
    :goto_1
    monitor-exit v0

    .line 40
    return-void

    .line 41
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    throw p0
.end method

.method public declared-synchronized e(Lio/n;)Laq/t;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    const-string v0, "MessengerIpcClient"

    .line 3
    .line 4
    const/4 v1, 0x3

    .line 5
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p1}, Lio/n;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "Queueing "

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, "MessengerIpcClient"

    .line 22
    .line 23
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception p1

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    :goto_0
    iget-object v0, p0, Lio/o;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Lio/m;

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Lio/m;->d(Lio/n;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    new-instance v0, Lio/m;

    .line 40
    .line 41
    invoke-direct {v0, p0}, Lio/m;-><init>(Lio/o;)V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Lio/o;->g:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {v0, p1}, Lio/m;->d(Lio/n;)Z

    .line 47
    .line 48
    .line 49
    :cond_1
    iget-object p1, p1, Lio/n;->b:Laq/k;

    .line 50
    .line 51
    iget-object p1, p1, Laq/k;->a:Laq/t;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    .line 53
    monitor-exit p0

    .line 54
    return-object p1

    .line 55
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 56
    throw p1
.end method

.method public g(I[B)[B
    .locals 1

    .line 1
    iget-object v0, p0, Lio/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lrr/c;

    .line 4
    .line 5
    iget p0, p0, Lio/o;->d:I

    .line 6
    .line 7
    if-gt p1, p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljavax/crypto/Mac;

    .line 14
    .line 15
    invoke-virtual {p0, p2}, Ljavax/crypto/Mac;->update([B)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Ljavax/crypto/Mac;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljavax/crypto/Mac;->doFinal()[B

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-static {p0, p1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_0
    new-instance p0, Ljava/security/InvalidAlgorithmParameterException;

    .line 34
    .line 35
    const-string p1, "tag size too big"

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/security/InvalidAlgorithmParameterException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0
.end method
