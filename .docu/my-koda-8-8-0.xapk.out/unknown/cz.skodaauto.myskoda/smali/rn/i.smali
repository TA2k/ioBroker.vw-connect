.class public final Lrn/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltn/b;
.implements Lpr/a;
.implements Lsl/e;
.implements Lu2/f;
.implements Ll9/d;
.implements Lk0/c;
.implements Lv9/a0;
.implements Lvp/l2;
.implements Lvp/q0;
.implements Lretrofit2/Converter;


# static fields
.field public static h:Lrn/i;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lrn/i;->d:I

    sparse-switch p1, :sswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    .line 75
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 76
    new-instance p1, Lt1/j0;

    const/16 v0, 0x9

    invoke-direct {p1, v0}, Lt1/j0;-><init>(I)V

    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 77
    new-instance p1, Lt1/j0;

    invoke-direct {p1, v0}, Lt1/j0;-><init>(I)V

    iput-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 78
    new-instance p1, Lt1/j0;

    invoke-direct {p1, v0}, Lt1/j0;-><init>(I)V

    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    return-void

    .line 79
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 80
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    sget-object v0, Lt2/c;->c:Lt2/h;

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 81
    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 82
    iput-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x8 -> :sswitch_1
        0xe -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/content/Context;Lvp/g1;)V
    .locals 9

    const/16 v0, 0x11

    iput v0, p0, Lrn/i;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicLong;

    const-wide/16 v1, -0x1

    invoke-direct {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    iput-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 5
    new-instance v7, Lno/q;

    const-string v0, "measurement:api"

    invoke-direct {v7, v0}, Lno/q;-><init>(Ljava/lang/String;)V

    .line 6
    new-instance v3, Lpo/b;

    .line 7
    sget-object v8, Lko/h;->c:Lko/h;

    const/4 v5, 0x0

    .line 8
    sget-object v6, Lpo/b;->n:Lc2/k;

    move-object v4, p1

    invoke-direct/range {v3 .. v8}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 9
    iput-object v3, p0, Lrn/i;->f:Ljava/lang/Object;

    iput-object p2, p0, Lrn/i;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/hardware/camera2/params/StreamConfigurationMap;Ly/a;)V
    .locals 2

    const/16 v0, 0xc

    iput v0, p0, Lrn/i;->d:I

    .line 53
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 54
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 55
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 56
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 57
    new-instance v0, Lro/f;

    const/4 v1, 0x6

    .line 58
    invoke-direct {v0, p1, v1}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 59
    iput-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 60
    iput-object p2, p0, Lrn/i;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/net/ConnectivityManager;Lxl/f;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lrn/i;->d:I

    .line 67
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 68
    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 69
    iput-object p2, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 70
    new-instance p2, Ldm0/j;

    const/4 v0, 0x3

    invoke-direct {p2, p0, v0}, Ldm0/j;-><init>(Ljava/lang/Object;I)V

    iput-object p2, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 71
    new-instance p0, Landroid/net/NetworkRequest$Builder;

    invoke-direct {p0}, Landroid/net/NetworkRequest$Builder;-><init>()V

    const/16 v0, 0xc

    .line 72
    invoke-virtual {p0, v0}, Landroid/net/NetworkRequest$Builder;->addCapability(I)Landroid/net/NetworkRequest$Builder;

    move-result-object p0

    .line 73
    invoke-virtual {p0}, Landroid/net/NetworkRequest$Builder;->build()Landroid/net/NetworkRequest;

    move-result-object p0

    .line 74
    invoke-virtual {p1, p0, p2}, Landroid/net/ConnectivityManager;->registerNetworkCallback(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V

    return-void
.end method

.method public constructor <init>(Lb81/b;)V
    .locals 4

    const/16 v0, 0x9

    iput v0, p0, Lrn/i;->d:I

    .line 92
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 93
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 94
    iget-object p1, p1, Lb81/b;->f:Ljava/lang/Object;

    check-cast p1, Lu/y;

    .line 95
    iget-object p1, p1, Lu/y;->g:Lj0/c;

    .line 96
    new-instance v0, Lu/v;

    invoke-direct {v0, p0, v1}, Lu/v;-><init>(Lrn/i;I)V

    const-wide/16 v1, 0x7d0

    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p1, v0, v1, v2, v3}, Lj0/c;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object p1

    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/w;Lrb0/a;Ls6/c;Ljava/util/Set;)V
    .locals 7

    const/4 v0, 0x5

    iput v0, p0, Lrn/i;->d:I

    .line 83
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 84
    iput-object p2, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 85
    iput-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 86
    iput-object p3, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 87
    invoke-interface {p4}, Ljava/util/Set;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_1

    .line 88
    :cond_0
    invoke-interface {p4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [I

    .line 89
    new-instance v1, Ljava/lang/String;

    const/4 p3, 0x0

    array-length p4, p2

    invoke-direct {v1, p2, p3, p4}, Ljava/lang/String;-><init>([III)V

    .line 90
    new-instance v6, Les/a;

    const/4 p2, 0x0

    invoke-direct {v6, v1, p2}, Les/a;-><init>(Ljava/lang/String;Z)V

    .line 91
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v3

    const/4 v4, 0x1

    const/4 v5, 0x1

    const/4 v2, 0x0

    move-object v0, p0

    invoke-virtual/range {v0 .. v6}, Lrn/i;->x(Ljava/lang/CharSequence;IIIZLs6/l;)Ljava/lang/Object;

    goto :goto_0

    :cond_1
    :goto_1
    return-void
.end method

.method public constructor <init>(Ld01/d0;Lqz0/a;Lt1/j0;)V
    .locals 1

    const/16 v0, 0x1a

    iput v0, p0, Lrn/i;->d:I

    const-string v0, "contentType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "serializer"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 12
    iput-object p2, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 13
    iput-object p3, p0, Lrn/i;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/io/Serializable;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lrn/i;->d:I

    iput-object p2, p0, Lrn/i;->e:Ljava/lang/Object;

    iput-object p3, p0, Lrn/i;->f:Ljava/lang/Object;

    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Lrn/i;->d:I

    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lrn/i;->f:Ljava/lang/Object;

    iput-object p3, p0, Lrn/i;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;I)V
    .locals 0

    .line 3
    iput p4, p0, Lrn/i;->d:I

    iput-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    iput-object p2, p0, Lrn/i;->e:Ljava/lang/Object;

    iput-object p3, p0, Lrn/i;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    const/16 v0, 0xf

    iput v0, p0, Lrn/i;->d:I

    .line 61
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 62
    new-instance v0, Lt7/n;

    invoke-direct {v0}, Lt7/n;-><init>()V

    .line 63
    const-string v1, "video/mp2t"

    invoke-static {v1}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, v0, Lt7/n;->l:Ljava/lang/String;

    .line 64
    invoke-static {p1}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, v0, Lt7/n;->m:Ljava/lang/String;

    .line 65
    new-instance p1, Lt7/o;

    invoke-direct {p1, v0}, Lt7/o;-><init>(Lt7/n;)V

    .line 66
    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/util/HashMap;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lrn/i;->d:I

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 39
    iput-object p2, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 40
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 6

    const/16 v0, 0xb

    iput v0, p0, Lrn/i;->d:I

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 30
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    mul-int/lit8 v0, v0, 0x2

    new-array v0, v0, [J

    iput-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 31
    :goto_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ge v0, v1, :cond_0

    .line 32
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lu9/c;

    mul-int/lit8 v2, v0, 0x2

    .line 33
    iget-object v3, p0, Lrn/i;->f:Ljava/lang/Object;

    check-cast v3, [J

    iget-wide v4, v1, Lu9/c;->b:J

    aput-wide v4, v3, v2

    add-int/lit8 v2, v2, 0x1

    .line 34
    iget-wide v4, v1, Lu9/c;->c:J

    aput-wide v4, v3, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    .line 35
    :cond_0
    iget-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    check-cast p1, [J

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    move-result-object p1

    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 36
    invoke-static {p1}, Ljava/util/Arrays;->sort([J)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 4

    const/16 v0, 0x17

    iput v0, p0, Lrn/i;->d:I

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 16
    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 17
    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 18
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_0

    .line 19
    iget-object v1, p0, Lrn/i;->e:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcn/f;

    .line 20
    iget-object v2, v2, Lcn/f;->b:Lbn/a;

    .line 21
    new-instance v3, Lxm/l;

    .line 22
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    check-cast v2, Ljava/util/List;

    .line 23
    invoke-direct {v3, v2}, Lxm/l;-><init>(Ljava/util/List;)V

    .line 24
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 25
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcn/f;

    .line 26
    iget-object v1, v1, Lcn/f;->c:Lbn/a;

    .line 27
    iget-object v2, p0, Lrn/i;->f:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    invoke-virtual {v1}, Lbn/a;->p()Lxm/e;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public constructor <init>([B)V
    .locals 3

    const/4 v0, 0x2

    iput v0, p0, Lrn/i;->d:I

    .line 41
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 42
    array-length v0, p1

    sget v1, Lrr/f;->a:I

    const/16 v1, 0x10

    if-eq v0, v1, :cond_1

    const/16 v2, 0x20

    if-ne v0, v2, :cond_0

    goto :goto_0

    .line 43
    :cond_0
    new-instance p0, Ljava/security/InvalidAlgorithmParameterException;

    mul-int/lit8 v0, v0, 0x8

    .line 44
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 45
    const-string v0, "invalid key size %d; only 128-bit and 256-bit AES keys are supported"

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/security/InvalidAlgorithmParameterException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 46
    :cond_1
    :goto_0
    new-instance v0, Ljavax/crypto/spec/SecretKeySpec;

    const-string v2, "AES"

    invoke-direct {v0, p1, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    iput-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 47
    sget-object p1, Lrr/a;->e:Lrr/a;

    const-string v2, "AES/ECB/NoPadding"

    invoke-virtual {p1, v2}, Lrr/a;->a(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljavax/crypto/Cipher;

    const/4 v2, 0x1

    .line 48
    invoke-virtual {p1, v2, v0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 49
    new-array v0, v1, [B

    .line 50
    invoke-virtual {p1, v0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object p1

    .line 51
    invoke-static {p1}, Lkp/b6;->a([B)[B

    move-result-object p1

    iput-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 52
    invoke-static {p1}, Lkp/b6;->a([B)[B

    move-result-object p1

    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    return-void
.end method

.method public static final m(Lrn/i;Landroid/net/Network;Z)V
    .locals 7

    .line 1
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/net/ConnectivityManager;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getAllNetworks()[Landroid/net/Network;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    array-length v1, v0

    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    if-ge v3, v1, :cond_3

    .line 13
    .line 14
    aget-object v4, v0, v3

    .line 15
    .line 16
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    const/4 v6, 0x1

    .line 21
    if-eqz v5, :cond_0

    .line 22
    .line 23
    move v4, p2

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    iget-object v5, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v5, Landroid/net/ConnectivityManager;

    .line 28
    .line 29
    invoke-virtual {v5, v4}, Landroid/net/ConnectivityManager;->getNetworkCapabilities(Landroid/net/Network;)Landroid/net/NetworkCapabilities;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    const/16 v5, 0xc

    .line 36
    .line 37
    invoke-virtual {v4, v5}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    move v4, v6

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    move v4, v2

    .line 46
    :goto_1
    if-eqz v4, :cond_2

    .line 47
    .line 48
    move v2, v6

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    :goto_2
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lxl/f;

    .line 56
    .line 57
    iget-object p1, p0, Lxl/f;->e:Ljava/lang/ref/WeakReference;

    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    check-cast p1, Lil/j;

    .line 64
    .line 65
    if-eqz p1, :cond_4

    .line 66
    .line 67
    iput-boolean v2, p0, Lxl/f;->g:Z

    .line 68
    .line 69
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_4
    const/4 p1, 0x0

    .line 73
    :goto_3
    if-nez p1, :cond_5

    .line 74
    .line 75
    invoke-virtual {p0}, Lxl/f;->a()V

    .line 76
    .line 77
    .line 78
    :cond_5
    return-void
.end method

.method public static q(Ljava/lang/String;Ljava/util/HashMap;)Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Ljava/util/Map$Entry;

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v2, "="

    .line 30
    .line 31
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    const-string v4, ""

    .line 39
    .line 40
    const-string v5, "UTF-8"

    .line 41
    .line 42
    if-eqz v3, :cond_0

    .line 43
    .line 44
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v5}, Ljava/net/URLEncoder;->encode(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    move-object v1, v4

    .line 56
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    const-string v3, "&"

    .line 64
    .line 65
    if-eqz v1, :cond_2

    .line 66
    .line 67
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    check-cast v1, Ljava/util/Map$Entry;

    .line 72
    .line 73
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    check-cast v3, Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    if-eqz v3, :cond_1

    .line 93
    .line 94
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    check-cast v1, Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v1, v5}, Ljava/net/URLEncoder;->encode(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    goto :goto_2

    .line 105
    :cond_1
    move-object v1, v4

    .line 106
    :goto_2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-eqz v0, :cond_3

    .line 119
    .line 120
    return-object p0

    .line 121
    :cond_3
    const-string v0, "?"

    .line 122
    .line 123
    invoke-virtual {p0, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-eqz v1, :cond_5

    .line 128
    .line 129
    invoke-virtual {p0, v3}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    if-nez v0, :cond_4

    .line 134
    .line 135
    invoke-virtual {v3, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    :cond_4
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0

    .line 144
    :cond_5
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0
.end method

.method public static r(Landroid/text/Editable;Landroid/view/KeyEvent;Z)Z
    .locals 6

    .line 1
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getMetaState()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-static {p1}, Landroid/view/KeyEvent;->metaStateHasNoModifiers(I)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v0, 0x0

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-static {p0}, Landroid/text/Selection;->getSelectionStart(Ljava/lang/CharSequence;)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-static {p0}, Landroid/text/Selection;->getSelectionEnd(Ljava/lang/CharSequence;)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, -0x1

    .line 22
    if-eq p1, v2, :cond_6

    .line 23
    .line 24
    if-eq v1, v2, :cond_6

    .line 25
    .line 26
    if-eq p1, v1, :cond_1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const-class v2, Ls6/u;

    .line 30
    .line 31
    invoke-interface {p0, p1, v1, v2}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, [Ls6/u;

    .line 36
    .line 37
    if-eqz v1, :cond_6

    .line 38
    .line 39
    array-length v2, v1

    .line 40
    if-lez v2, :cond_6

    .line 41
    .line 42
    array-length v2, v1

    .line 43
    move v3, v0

    .line 44
    :goto_0
    if-ge v3, v2, :cond_6

    .line 45
    .line 46
    aget-object v4, v1, v3

    .line 47
    .line 48
    invoke-interface {p0, v4}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    invoke-interface {p0, v4}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz p2, :cond_2

    .line 57
    .line 58
    if-eq v5, p1, :cond_4

    .line 59
    .line 60
    :cond_2
    if-nez p2, :cond_3

    .line 61
    .line 62
    if-eq v4, p1, :cond_4

    .line 63
    .line 64
    :cond_3
    if-le p1, v5, :cond_5

    .line 65
    .line 66
    if-ge p1, v4, :cond_5

    .line 67
    .line 68
    :cond_4
    invoke-interface {p0, v5, v4}, Landroid/text/Editable;->delete(II)Landroid/text/Editable;

    .line 69
    .line 70
    .line 71
    const/4 p0, 0x1

    .line 72
    return p0

    .line 73
    :cond_5
    add-int/lit8 v3, v3, 0x1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_6
    :goto_1
    return v0
.end method


# virtual methods
.method public A(Ljava/lang/Object;)V
    .locals 5

    .line 1
    invoke-static {}, Lt2/c;->d()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sget-wide v2, Lt2/i;->a:J

    .line 6
    .line 7
    cmp-long v2, v0, v2

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v2, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v2

    .line 17
    :try_start_0
    iget-object v3, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v3, Ljava/util/concurrent/atomic/AtomicReference;

    .line 20
    .line 21
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    check-cast v3, Lt2/h;

    .line 26
    .line 27
    invoke-virtual {v3, v0, v1}, Lt2/h;->a(J)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-gez v4, :cond_1

    .line 32
    .line 33
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 36
    .line 37
    invoke-virtual {v3, v0, v1, p1}, Lt2/h;->b(JLjava/lang/Object;)Lt2/h;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    monitor-exit v2

    .line 45
    return-void

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_0

    .line 48
    :cond_1
    :try_start_1
    iget-object p0, v3, Lt2/h;->c:[Ljava/lang/Object;

    .line 49
    .line 50
    aput-object p1, p0, v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    .line 52
    monitor-exit v2

    .line 53
    return-void

    .line 54
    :goto_0
    monitor-exit v2

    .line 55
    throw p0
.end method

.method public B(Ljava/lang/String;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 7
    .line 8
    const-string p1, "Null backendName"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public C()V
    .locals 3

    .line 1
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, Ljava/util/List;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lay0/a;

    .line 20
    .line 21
    invoke-interface {v2, p0}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    :cond_0
    move-object p0, v2

    .line 25
    check-cast p0, Ljava/util/Collection;

    .line 26
    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    invoke-virtual {v0, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_2
    :goto_0
    return-void
.end method

.method public declared-synchronized D(JIIJ)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-object v0, v1, Lrn/i;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lvp/g1;

    .line 7
    .line 8
    iget-object v0, v0, Lvp/g1;->n:Lto/a;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    iget-object v0, v1, Lrn/i;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 22
    .line 23
    .line 24
    move-result-wide v4

    .line 25
    const-wide/16 v6, -0x1

    .line 26
    .line 27
    cmp-long v4, v4, v6

    .line 28
    .line 29
    if-nez v4, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 33
    .line 34
    .line 35
    move-result-wide v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    sub-long v4, v2, v4

    .line 37
    .line 38
    const-wide/32 v6, 0x1b7740

    .line 39
    .line 40
    .line 41
    cmp-long v0, v4, v6

    .line 42
    .line 43
    if-gtz v0, :cond_1

    .line 44
    .line 45
    monitor-exit p0

    .line 46
    return-void

    .line 47
    :cond_1
    :goto_0
    :try_start_1
    iget-object v0, v1, Lrn/i;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Lpo/b;

    .line 50
    .line 51
    new-instance v4, Lno/p;

    .line 52
    .line 53
    new-instance v5, Lno/l;

    .line 54
    .line 55
    const/4 v14, 0x0

    .line 56
    const/4 v15, 0x0

    .line 57
    const v6, 0x8dcd

    .line 58
    .line 59
    .line 60
    const/4 v8, 0x0

    .line 61
    const/4 v13, 0x0

    .line 62
    move-wide/from16 v9, p1

    .line 63
    .line 64
    move/from16 v7, p3

    .line 65
    .line 66
    move/from16 v16, p4

    .line 67
    .line 68
    move-wide/from16 v11, p5

    .line 69
    .line 70
    invoke-direct/range {v5 .. v16}, Lno/l;-><init>(IIIJJLjava/lang/String;Ljava/lang/String;II)V

    .line 71
    .line 72
    .line 73
    filled-new-array {v5}, [Lno/l;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    invoke-static {v5}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    const/4 v6, 0x0

    .line 82
    invoke-direct {v4, v6, v5}, Lno/p;-><init>(ILjava/util/List;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, v4}, Lpo/b;->f(Lno/p;)Laq/t;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    new-instance v4, Lg1/i3;

    .line 90
    .line 91
    const/4 v5, 0x5

    .line 92
    invoke-direct {v4, v1, v2, v3, v5}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, v4}, Laq/t;->l(Laq/f;)Laq/t;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 96
    .line 97
    .line 98
    monitor-exit p0

    .line 99
    return-void

    .line 100
    :catchall_0
    move-exception v0

    .line 101
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 102
    throw v0
.end method

.method public a(Lw7/u;Lo8/q;Lh11/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-virtual {p3}, Lh11/h;->d()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3}, Lh11/h;->i()V

    .line 7
    .line 8
    .line 9
    iget p1, p3, Lh11/h;->f:I

    .line 10
    .line 11
    const/4 p3, 0x5

    .line 12
    invoke-interface {p2, p1, p3}, Lo8/q;->q(II)Lo8/i0;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 17
    .line 18
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lt7/o;

    .line 21
    .line 22
    invoke-interface {p1, p0}, Lo8/i0;->c(Lt7/o;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public b(Lw7/p;)V
    .locals 13

    .line 1
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lw7/u;

    .line 4
    .line 5
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v1, v0

    .line 13
    check-cast v1, Lw7/u;

    .line 14
    .line 15
    monitor-enter v1

    .line 16
    :try_start_0
    iget-wide v2, v1, Lw7/u;->c:J

    .line 17
    .line 18
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    cmp-long v0, v2, v4

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget-wide v6, v1, Lw7/u;->b:J

    .line 28
    .line 29
    add-long/2addr v2, v6

    .line 30
    :goto_0
    move-wide v7, v2

    .line 31
    goto :goto_1

    .line 32
    :catchall_0
    move-exception v0

    .line 33
    move-object p0, v0

    .line 34
    goto :goto_3

    .line 35
    :cond_0
    invoke-virtual {v1}, Lw7/u;->d()J

    .line 36
    .line 37
    .line 38
    move-result-wide v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    goto :goto_0

    .line 40
    :goto_1
    monitor-exit v1

    .line 41
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v2, v0

    .line 44
    check-cast v2, Lw7/u;

    .line 45
    .line 46
    monitor-enter v2

    .line 47
    :try_start_1
    iget-wide v0, v2, Lw7/u;->b:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 48
    .line 49
    monitor-exit v2

    .line 50
    cmp-long v2, v7, v4

    .line 51
    .line 52
    if-eqz v2, :cond_3

    .line 53
    .line 54
    cmp-long v2, v0, v4

    .line 55
    .line 56
    if-nez v2, :cond_1

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_1
    iget-object v2, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Lt7/o;

    .line 62
    .line 63
    iget-wide v3, v2, Lt7/o;->s:J

    .line 64
    .line 65
    cmp-long v3, v0, v3

    .line 66
    .line 67
    if-eqz v3, :cond_2

    .line 68
    .line 69
    invoke-virtual {v2}, Lt7/o;->a()Lt7/n;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    iput-wide v0, v2, Lt7/n;->r:J

    .line 74
    .line 75
    new-instance v0, Lt7/o;

    .line 76
    .line 77
    invoke-direct {v0, v2}, Lt7/o;-><init>(Lt7/n;)V

    .line 78
    .line 79
    .line 80
    iput-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 81
    .line 82
    iget-object v1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v1, Lo8/i0;

    .line 85
    .line 86
    invoke-interface {v1, v0}, Lo8/i0;->c(Lt7/o;)V

    .line 87
    .line 88
    .line 89
    :cond_2
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 90
    .line 91
    .line 92
    move-result v10

    .line 93
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lo8/i0;

    .line 96
    .line 97
    const/4 v1, 0x0

    .line 98
    invoke-interface {v0, p1, v10, v1}, Lo8/i0;->a(Lw7/p;II)V

    .line 99
    .line 100
    .line 101
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 102
    .line 103
    move-object v6, p0

    .line 104
    check-cast v6, Lo8/i0;

    .line 105
    .line 106
    const/4 v11, 0x0

    .line 107
    const/4 v12, 0x0

    .line 108
    const/4 v9, 0x1

    .line 109
    invoke-interface/range {v6 .. v12}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 110
    .line 111
    .line 112
    :cond_3
    :goto_2
    return-void

    .line 113
    :catchall_1
    move-exception v0

    .line 114
    move-object p0, v0

    .line 115
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 116
    throw p0

    .line 117
    :goto_3
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 118
    throw p0
.end method

.method public c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lrn/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Void;

    .line 7
    .line 8
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lw0/c;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iput-object p1, p0, Lw0/c;->e:Lk0/d;

    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 17
    .line 18
    iget-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Lcom/google/android/material/datepicker/d;

    .line 21
    .line 22
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Lb0/u;

    .line 25
    .line 26
    iput-object v0, p1, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 27
    .line 28
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Landroid/content/Context;

    .line 31
    .line 32
    invoke-static {p0}, Llp/i1;->a(Landroid/content/Context;)Landroid/content/Context;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    iput-object p0, p1, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_data_0
    .packed-switch 0xd
        :pswitch_0
    .end packed-switch
.end method

.method public d()Z
    .locals 6

    .line 1
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/net/ConnectivityManager;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/net/ConnectivityManager;->getAllNetworks()[Landroid/net/Network;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    array-length v1, v0

    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    if-ge v3, v1, :cond_1

    .line 13
    .line 14
    aget-object v4, v0, v3

    .line 15
    .line 16
    invoke-virtual {p0, v4}, Landroid/net/ConnectivityManager;->getNetworkCapabilities(Landroid/net/Network;)Landroid/net/NetworkCapabilities;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    if-eqz v4, :cond_0

    .line 21
    .line 22
    const/16 v5, 0xc

    .line 23
    .line 24
    invoke-virtual {v4, v5}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-eqz v4, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    return v2
.end method

.method public e(J)I
    .locals 1

    .line 1
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [J

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-static {p0, p1, p2, v0}, Lw7/w;->a([JJZ)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    array-length p0, p0

    .line 11
    if-ge p1, p0, :cond_0

    .line 12
    .line 13
    return p1

    .line 14
    :cond_0
    const/4 p0, -0x1

    .line 15
    return p0
.end method

.method public f(J)Ljava/util/List;
    .locals 9

    .line 1
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/List;

    .line 4
    .line 5
    new-instance v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    move v4, v3

    .line 17
    :goto_0
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    if-ge v4, v5, :cond_2

    .line 22
    .line 23
    iget-object v5, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v5, [J

    .line 26
    .line 27
    mul-int/lit8 v6, v4, 0x2

    .line 28
    .line 29
    aget-wide v7, v5, v6

    .line 30
    .line 31
    cmp-long v7, v7, p1

    .line 32
    .line 33
    if-gtz v7, :cond_1

    .line 34
    .line 35
    add-int/lit8 v6, v6, 0x1

    .line 36
    .line 37
    aget-wide v5, v5, v6

    .line 38
    .line 39
    cmp-long v5, p1, v5

    .line 40
    .line 41
    if-gez v5, :cond_1

    .line 42
    .line 43
    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v5

    .line 47
    check-cast v5, Lu9/c;

    .line 48
    .line 49
    iget-object v6, v5, Lu9/c;->a:Lv7/b;

    .line 50
    .line 51
    iget v7, v6, Lv7/b;->e:F

    .line 52
    .line 53
    const v8, -0x800001

    .line 54
    .line 55
    .line 56
    cmpl-float v7, v7, v8

    .line 57
    .line 58
    if-nez v7, :cond_0

    .line 59
    .line 60
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_0
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    :cond_1
    :goto_1
    add-int/lit8 v4, v4, 0x1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 71
    .line 72
    const/16 p1, 0x19

    .line 73
    .line 74
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 75
    .line 76
    .line 77
    invoke-static {v2, p0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 78
    .line 79
    .line 80
    :goto_2
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    if-ge v3, p0, :cond_3

    .line 85
    .line 86
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, Lu9/c;

    .line 91
    .line 92
    iget-object p0, p0, Lu9/c;->a:Lv7/b;

    .line 93
    .line 94
    invoke-virtual {p0}, Lv7/b;->a()Lv7/a;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    rsub-int/lit8 p1, v3, -0x1

    .line 99
    .line 100
    int-to-float p1, p1

    .line 101
    iput p1, p0, Lv7/a;->e:F

    .line 102
    .line 103
    const/4 p1, 0x1

    .line 104
    iput p1, p0, Lv7/a;->f:I

    .line 105
    .line 106
    invoke-virtual {p0}, Lv7/a;->a()Lv7/b;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    add-int/lit8 v3, v3, 0x1

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_3
    return-object v1
.end method

.method public g(I[B)[B
    .locals 9

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    if-gt p1, v0, :cond_5

    .line 4
    .line 5
    sget-object v1, Lrr/a;->e:Lrr/a;

    .line 6
    .line 7
    const-string v2, "AES/ECB/NoPadding"

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Lrr/a;->a(Ljava/lang/String;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Ljavax/crypto/Cipher;

    .line 14
    .line 15
    iget-object v2, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v2, Ljavax/crypto/spec/SecretKeySpec;

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    invoke-virtual {v1, v3, v2}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 21
    .line 22
    .line 23
    array-length v2, p2

    .line 24
    int-to-double v4, v2

    .line 25
    const-wide/high16 v6, 0x4030000000000000L    # 16.0

    .line 26
    .line 27
    div-double/2addr v4, v6

    .line 28
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 29
    .line 30
    .line 31
    move-result-wide v4

    .line 32
    double-to-int v2, v4

    .line 33
    invoke-static {v3, v2}, Ljava/lang/Math;->max(II)I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    mul-int/lit8 v4, v2, 0x10

    .line 38
    .line 39
    array-length v5, p2

    .line 40
    const-string v6, "The lengths of x and y should match."

    .line 41
    .line 42
    const/4 v7, 0x0

    .line 43
    if-ne v4, v5, :cond_0

    .line 44
    .line 45
    add-int/lit8 v4, v2, -0x1

    .line 46
    .line 47
    mul-int/2addr v4, v0

    .line 48
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, [B

    .line 51
    .line 52
    invoke-static {v4, v7, v0, p2, p0}, Lkp/c6;->c(III[B[B)[B

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    add-int/lit8 v4, v2, -0x1

    .line 58
    .line 59
    mul-int/2addr v4, v0

    .line 60
    array-length v5, p2

    .line 61
    invoke-static {p2, v4, v5}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    array-length v5, v4

    .line 66
    if-ge v5, v0, :cond_4

    .line 67
    .line 68
    invoke-static {v4, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    array-length v4, v4

    .line 73
    const/16 v8, -0x80

    .line 74
    .line 75
    aput-byte v8, v5, v4

    .line 76
    .line 77
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, [B

    .line 80
    .line 81
    array-length v4, v5

    .line 82
    array-length v8, p0

    .line 83
    if-ne v4, v8, :cond_3

    .line 84
    .line 85
    array-length v4, v5

    .line 86
    invoke-static {v7, v7, v4, v5, p0}, Lkp/c6;->c(III[B[B)[B

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    :goto_0
    new-array v4, v0, [B

    .line 91
    .line 92
    move v5, v7

    .line 93
    :goto_1
    add-int/lit8 v8, v2, -0x1

    .line 94
    .line 95
    if-ge v5, v8, :cond_1

    .line 96
    .line 97
    mul-int/lit8 v8, v5, 0x10

    .line 98
    .line 99
    invoke-static {v7, v8, v0, v4, p2}, Lkp/c6;->c(III[B[B)[B

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-virtual {v1, v4}, Ljavax/crypto/Cipher;->doFinal([B)[B

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    add-int/lit8 v5, v5, 0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_1
    array-length p2, p0

    .line 111
    array-length v0, v4

    .line 112
    if-ne p2, v0, :cond_2

    .line 113
    .line 114
    array-length p2, p0

    .line 115
    invoke-static {v7, v7, p2, p0, v4}, Lkp/c6;->c(III[B[B)[B

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-virtual {v1, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-static {p0, p1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 129
    .line 130
    invoke-direct {p0, v6}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw p0

    .line 134
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 135
    .line 136
    invoke-direct {p0, v6}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 141
    .line 142
    const-string p1, "x must be smaller than a block."

    .line 143
    .line 144
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0

    .line 148
    :cond_5
    new-instance p0, Ljava/security/InvalidAlgorithmParameterException;

    .line 149
    .line 150
    const-string p1, "outputLength too large, max is 16 bytes"

    .line 151
    .line 152
    invoke-direct {p0, p1}, Ljava/security/InvalidAlgorithmParameterException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p0
.end method

.method public get()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lrn/i;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lkx0/a;

    .line 9
    .line 10
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Landroid/content/Context;

    .line 15
    .line 16
    iget-object v1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Lkx0/a;

    .line 19
    .line 20
    invoke-interface {v1}, Lkx0/a;->get()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Lyn/d;

    .line 25
    .line 26
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lpy/a;

    .line 29
    .line 30
    invoke-virtual {p0}, Lpy/a;->get()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lxn/a;

    .line 35
    .line 36
    new-instance v2, Lrn/i;

    .line 37
    .line 38
    const/16 v3, 0x18

    .line 39
    .line 40
    invoke-direct {v2, v0, v1, p0, v3}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    return-object v2

    .line 44
    :sswitch_0
    invoke-static {}, Lt2/c;->d()J

    .line 45
    .line 46
    .line 47
    move-result-wide v0

    .line 48
    sget-wide v2, Lt2/i;->a:J

    .line 49
    .line 50
    cmp-long v2, v0, v2

    .line 51
    .line 52
    if-nez v2, :cond_0

    .line 53
    .line 54
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_0
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lt2/h;

    .line 66
    .line 67
    invoke-virtual {p0, v0, v1}, Lt2/h;->a(J)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-ltz v0, :cond_1

    .line 72
    .line 73
    iget-object p0, p0, Lt2/h;->c:[Ljava/lang/Object;

    .line 74
    .line 75
    aget-object p0, p0, v0

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_1
    const/4 p0, 0x0

    .line 79
    :goto_0
    return-object p0

    .line 80
    :sswitch_1
    new-instance v1, La61/a;

    .line 81
    .line 82
    const/4 v0, 0x2

    .line 83
    invoke-direct {v1, v0}, La61/a;-><init>(I)V

    .line 84
    .line 85
    .line 86
    new-instance v2, Lwq/f;

    .line 87
    .line 88
    const/4 v0, 0x1

    .line 89
    invoke-direct {v2, v0}, Lwq/f;-><init>(I)V

    .line 90
    .line 91
    .line 92
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v0, Landroidx/lifecycle/c1;

    .line 95
    .line 96
    invoke-virtual {v0}, Landroidx/lifecycle/c1;->get()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    move-object v3, v0

    .line 101
    check-cast v3, Lwn/b;

    .line 102
    .line 103
    iget-object v0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v0, Lss/b;

    .line 106
    .line 107
    invoke-virtual {v0}, Lss/b;->get()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    move-object v4, v0

    .line 112
    check-cast v4, Lqn/s;

    .line 113
    .line 114
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast p0, Lun/a;

    .line 117
    .line 118
    invoke-virtual {p0}, Lun/a;->get()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    move-object v5, p0

    .line 123
    check-cast v5, Lun/a;

    .line 124
    .line 125
    new-instance v0, Lrn/r;

    .line 126
    .line 127
    invoke-direct/range {v0 .. v5}, Lrn/r;-><init>(Lao/a;Lao/a;Lwn/b;Lqn/s;Lun/a;)V

    .line 128
    .line 129
    .line 130
    return-object v0

    .line 131
    :sswitch_data_0
    .sparse-switch
        0x1 -> :sswitch_1
        0x8 -> :sswitch_0
    .end sparse-switch
.end method

.method public h(ILjava/lang/Throwable;[B)V
    .locals 7

    .line 1
    iget-object p3, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p3, Lvp/j2;

    .line 4
    .line 5
    invoke-virtual {p3}, Lvp/x;->a0()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lvp/r3;

    .line 11
    .line 12
    const/16 v1, 0xc8

    .line 13
    .line 14
    if-eq p1, v1, :cond_0

    .line 15
    .line 16
    const/16 v1, 0xcc

    .line 17
    .line 18
    if-eq p1, v1, :cond_0

    .line 19
    .line 20
    const/16 v1, 0x130

    .line 21
    .line 22
    if-ne p1, v1, :cond_1

    .line 23
    .line 24
    move p1, v1

    .line 25
    :cond_0
    if-nez p2, :cond_1

    .line 26
    .line 27
    iget-object p1, p3, Lap0/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Lvp/g1;

    .line 30
    .line 31
    iget-object p1, p1, Lvp/g1;->i:Lvp/p0;

    .line 32
    .line 33
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p1, Lvp/p0;->r:Lvp/n0;

    .line 37
    .line 38
    iget-wide v1, v0, Lvp/r3;->d:J

    .line 39
    .line 40
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 41
    .line 42
    .line 43
    move-result-object p2

    .line 44
    const-string v1, "[sgtm] Upload succeeded for row_id"

    .line 45
    .line 46
    invoke-virtual {p1, p2, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    sget-object p1, Lvp/p2;->f:Lvp/p2;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    iget-object v1, p3, Lap0/o;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v1, Lvp/g1;

    .line 55
    .line 56
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 57
    .line 58
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 62
    .line 63
    iget-wide v2, v0, Lvp/r3;->d:J

    .line 64
    .line 65
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const-string v4, "[sgtm] Upload failed for row_id. response, exception"

    .line 74
    .line 75
    invoke-virtual {v1, v4, v2, v3, p2}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    sget-object p2, Lvp/z;->u:Lvp/y;

    .line 79
    .line 80
    const/4 v1, 0x0

    .line 81
    invoke-virtual {p2, v1}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    check-cast p2, Ljava/lang/String;

    .line 86
    .line 87
    const-string v1, ","

    .line 88
    .line 89
    invoke-virtual {p2, v1}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    invoke-static {p2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-interface {p2, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_2

    .line 106
    .line 107
    sget-object p1, Lvp/p2;->h:Lvp/p2;

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_2
    sget-object p1, Lvp/p2;->g:Lvp/p2;

    .line 111
    .line 112
    :goto_0
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 115
    .line 116
    iget-object p2, p3, Lap0/o;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p2, Lvp/g1;

    .line 119
    .line 120
    invoke-virtual {p2}, Lvp/g1;->o()Lvp/d3;

    .line 121
    .line 122
    .line 123
    move-result-object p2

    .line 124
    new-instance v1, Lvp/e;

    .line 125
    .line 126
    iget-wide v3, v0, Lvp/r3;->d:J

    .line 127
    .line 128
    iget v2, p1, Lvp/p2;->d:I

    .line 129
    .line 130
    iget-wide v5, v0, Lvp/r3;->i:J

    .line 131
    .line 132
    invoke-direct/range {v1 .. v6}, Lvp/e;-><init>(IJJ)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p2}, Lvp/x;->a0()V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p2}, Lvp/b0;->b0()V

    .line 139
    .line 140
    .line 141
    const/4 v0, 0x1

    .line 142
    invoke-virtual {p2, v0}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    new-instance v2, Lio/i;

    .line 147
    .line 148
    const/16 v5, 0xb

    .line 149
    .line 150
    invoke-direct {v2, p2, v0, v1, v5}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p2, v2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 154
    .line 155
    .line 156
    iget-object p2, p3, Lap0/o;->e:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast p2, Lvp/g1;

    .line 159
    .line 160
    iget-object p2, p2, Lvp/g1;->i:Lvp/p0;

    .line 161
    .line 162
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 163
    .line 164
    .line 165
    iget-object p2, p2, Lvp/p0;->r:Lvp/n0;

    .line 166
    .line 167
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 168
    .line 169
    .line 170
    move-result-object p3

    .line 171
    const-string v0, "[sgtm] Updated status for row_id"

    .line 172
    .line 173
    invoke-virtual {p2, p3, p1, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    monitor-enter p0

    .line 177
    :try_start_0
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 181
    .line 182
    .line 183
    monitor-exit p0

    .line 184
    return-void

    .line 185
    :catchall_0
    move-exception v0

    .line 186
    move-object p1, v0

    .line 187
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 188
    throw p1
.end method

.method public i(I)J
    .locals 3

    .line 1
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [J

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    const/4 v1, 0x1

    .line 7
    if-ltz p1, :cond_0

    .line 8
    .line 9
    move v2, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v2, v0

    .line 12
    :goto_0
    invoke-static {v2}, Lw7/a;->c(Z)V

    .line 13
    .line 14
    .line 15
    array-length v2, p0

    .line 16
    if-ge p1, v2, :cond_1

    .line 17
    .line 18
    move v0, v1

    .line 19
    :cond_1
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 20
    .line 21
    .line 22
    aget-wide p0, p0, p1

    .line 23
    .line 24
    return-wide p0
.end method

.method public j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt1/j0;

    .line 4
    .line 5
    iget-object v1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ld01/d0;

    .line 8
    .line 9
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lqz0/a;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const-string v2, "contentType"

    .line 17
    .line 18
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v2, "saver"

    .line 22
    .line 23
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lqz0/j;

    .line 29
    .line 30
    check-cast v0, Lvz0/d;

    .line 31
    .line 32
    invoke-virtual {v0, p0, p1}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v1, p0}, Ld01/r0;->create(Ld01/d0;Ljava/lang/String;)Ld01/r0;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const-string p1, "create(contentType, string)"

    .line 41
    .line 42
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object p0
.end method

.method public k()I
    .locals 0

    .line 1
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [J

    .line 4
    .line 5
    array-length p0, p0

    .line 6
    return p0
.end method

.method public l(Ljava/lang/String;ILjava/lang/Throwable;[BLjava/util/Map;)V
    .locals 7

    .line 1
    iget p1, p0, Lrn/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lvp/a4;

    .line 9
    .line 10
    iget-wide v0, p1, Lvp/a4;->a:J

    .line 11
    .line 12
    iget-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Lvp/z3;

    .line 15
    .line 16
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p1}, Lvp/z3;->f()Lvp/e1;

    .line 21
    .line 22
    .line 23
    move-result-object p5

    .line 24
    invoke-virtual {p5}, Lvp/e1;->a0()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, Lvp/z3;->k0()V

    .line 28
    .line 29
    .line 30
    const/4 p5, 0x0

    .line 31
    if-nez p4, :cond_0

    .line 32
    .line 33
    :try_start_0
    new-array p4, p5, [B

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :catchall_0
    move-exception v0

    .line 37
    move-object p0, v0

    .line 38
    goto/16 :goto_2

    .line 39
    .line 40
    :cond_0
    :goto_0
    const/16 v2, 0xc8

    .line 41
    .line 42
    if-eq p2, v2, :cond_1

    .line 43
    .line 44
    const/16 v2, 0xcc

    .line 45
    .line 46
    if-ne p2, v2, :cond_3

    .line 47
    .line 48
    move p2, v2

    .line 49
    :cond_1
    if-nez p3, :cond_3

    .line 50
    .line 51
    iget-object p3, p1, Lvp/z3;->f:Lvp/n;

    .line 52
    .line 53
    invoke-static {p3}, Lvp/z3;->T(Lvp/u3;)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 57
    .line 58
    .line 59
    move-result-object p4

    .line 60
    invoke-virtual {p3, p4}, Lvp/n;->h0(Ljava/lang/Long;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1}, Lvp/z3;->d()Lvp/p0;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    iget-object p3, p3, Lvp/p0;->r:Lvp/n0;

    .line 68
    .line 69
    const-string p4, "Successfully uploaded batch from upload queue. appId, status"

    .line 70
    .line 71
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    invoke-virtual {p3, p0, p2, p4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object p2, p1, Lvp/z3;->e:Lvp/s0;

    .line 79
    .line 80
    invoke-static {p2}, Lvp/z3;->T(Lvp/u3;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2}, Lvp/s0;->u0()Z

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    if-eqz p2, :cond_2

    .line 88
    .line 89
    iget-object p2, p1, Lvp/z3;->f:Lvp/n;

    .line 90
    .line 91
    invoke-static {p2}, Lvp/z3;->T(Lvp/u3;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p2, p0}, Lvp/n;->g0(Ljava/lang/String;)Z

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    if-eqz p2, :cond_2

    .line 99
    .line 100
    invoke-virtual {p1, p0}, Lvp/z3;->t(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_2
    invoke-virtual {p1}, Lvp/z3;->N()V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    new-instance v2, Ljava/lang/String;

    .line 109
    .line 110
    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 111
    .line 112
    invoke-direct {v2, p4, v3}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 116
    .line 117
    .line 118
    move-result p4

    .line 119
    const/16 v3, 0x20

    .line 120
    .line 121
    invoke-static {v3, p4}, Ljava/lang/Math;->min(II)I

    .line 122
    .line 123
    .line 124
    move-result p4

    .line 125
    invoke-virtual {v2, p5, p4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p4

    .line 129
    invoke-virtual {p1}, Lvp/z3;->d()Lvp/p0;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    iget-object v2, v2, Lvp/p0;->o:Lvp/n0;

    .line 134
    .line 135
    const-string v3, "Network upload failed. Will retry later. appId, status, error"

    .line 136
    .line 137
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 138
    .line 139
    .line 140
    move-result-object p2

    .line 141
    if-nez p3, :cond_4

    .line 142
    .line 143
    move-object p3, p4

    .line 144
    :cond_4
    invoke-virtual {v2, v3, p0, p2, p3}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    iget-object p0, p1, Lvp/z3;->f:Lvp/n;

    .line 148
    .line 149
    invoke-static {p0}, Lvp/z3;->T(Lvp/u3;)V

    .line 150
    .line 151
    .line 152
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 153
    .line 154
    .line 155
    move-result-object p2

    .line 156
    invoke-virtual {p0, p2}, Lvp/n;->m0(Ljava/lang/Long;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p1}, Lvp/z3;->N()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 160
    .line 161
    .line 162
    :goto_1
    iput-boolean p5, p1, Lvp/z3;->x:Z

    .line 163
    .line 164
    invoke-virtual {p1}, Lvp/z3;->O()V

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :goto_2
    iput-boolean p5, p1, Lvp/z3;->x:Z

    .line 169
    .line 170
    invoke-virtual {p1}, Lvp/z3;->O()V

    .line 171
    .line 172
    .line 173
    throw p0

    .line 174
    :pswitch_0
    iget-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 175
    .line 176
    move-object v0, p1

    .line 177
    check-cast v0, Lvp/z3;

    .line 178
    .line 179
    iget-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 180
    .line 181
    move-object v5, p1

    .line 182
    check-cast v5, Ljava/lang/String;

    .line 183
    .line 184
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 185
    .line 186
    move-object v6, p0

    .line 187
    check-cast v6, Ljava/util/ArrayList;

    .line 188
    .line 189
    const/4 v1, 0x1

    .line 190
    move v2, p2

    .line 191
    move-object v3, p3

    .line 192
    move-object v4, p4

    .line 193
    invoke-virtual/range {v0 .. v6}, Lvp/z3;->y(ZILjava/lang/Throwable;[BLjava/lang/String;Ljava/util/List;)V

    .line 194
    .line 195
    .line 196
    return-void

    .line 197
    :pswitch_data_0
    .packed-switch 0x13
        :pswitch_0
    .end packed-switch
.end method

.method public n(Lv3/h0;Lv3/v;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt1/j0;

    .line 4
    .line 5
    iget-object v1, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lt1/j0;

    .line 8
    .line 9
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lt1/j0;

    .line 12
    .line 13
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    if-eqz p2, :cond_5

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    if-eq p2, v2, :cond_4

    .line 21
    .line 22
    const/4 v2, 0x2

    .line 23
    if-eq p2, v2, :cond_2

    .line 24
    .line 25
    const/4 v0, 0x3

    .line 26
    if-ne p2, v0, :cond_1

    .line 27
    .line 28
    iget-object p2, p1, Lv3/h0;->j:Lv3/h0;

    .line 29
    .line 30
    if-eqz p2, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    invoke-virtual {v1, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_1
    new-instance p0, La8/r0;

    .line 41
    .line 42
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :cond_2
    iget-object p2, p1, Lv3/h0;->j:Lv3/h0;

    .line 47
    .line 48
    if-eqz p2, :cond_3

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_3
    invoke-virtual {v0, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_4
    invoke-virtual {v1, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_5
    invoke-virtual {v0, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lt1/j0;->k(Lv3/h0;)V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public o()Lrn/j;
    .locals 3

    .line 1
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, " backendName"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, ""

    .line 11
    .line 12
    :goto_0
    iget-object v1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Lon/d;

    .line 15
    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    const-string v1, " priority"

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :cond_1
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_2

    .line 29
    .line 30
    new-instance v0, Lrn/j;

    .line 31
    .line 32
    iget-object v1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Ljava/lang/String;

    .line 35
    .line 36
    iget-object v2, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, [B

    .line 39
    .line 40
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lon/d;

    .line 43
    .line 44
    invoke-direct {v0, v1, v2, p0}, Lrn/j;-><init>(Ljava/lang/String;[BLon/d;)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string v1, "Missing required properties:"

    .line 51
    .line 52
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0
.end method

.method public p(Lv3/h0;)Z
    .locals 4

    .line 1
    iget-object v0, p1, Lv3/h0;->j:Lv3/h0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    iget-object v3, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v3, Lt1/j0;

    .line 13
    .line 14
    iget-object v3, v3, Lt1/j0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v3, Lv3/y1;

    .line 17
    .line 18
    invoke-virtual {v3, p1}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-nez v3, :cond_2

    .line 23
    .line 24
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lt1/j0;

    .line 27
    .line 28
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lv3/y1;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move p0, v1

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    :goto_1
    move p0, v2

    .line 42
    :goto_2
    if-nez v0, :cond_3

    .line 43
    .line 44
    if-eqz p0, :cond_3

    .line 45
    .line 46
    return v2

    .line 47
    :cond_3
    return v1
.end method

.method public s()Lrs/a;
    .locals 7

    .line 1
    const-string v0, "FirebaseCrashlytics"

    .line 2
    .line 3
    const-string v1, "GET Request URL: "

    .line 4
    .line 5
    invoke-static {}, Lns/d;->b()V

    .line 6
    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    :try_start_0
    iget-object v3, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Ljava/lang/String;

    .line 12
    .line 13
    iget-object v4, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v4, Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-static {v3, v4}, Lrn/i;->q(Ljava/lang/String;Ljava/util/HashMap;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    new-instance v4, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    invoke-direct {v4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const/4 v4, 0x2

    .line 34
    invoke-static {v0, v4}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_0

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 41
    .line 42
    .line 43
    :cond_0
    new-instance v0, Ljava/net/URL;

    .line 44
    .line 45
    invoke-direct {v0, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Ljavax/net/ssl/HttpsURLConnection;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 53
    .line 54
    const/16 v1, 0x2710

    .line 55
    .line 56
    :try_start_1
    invoke-virtual {v0, v1}, Ljava/net/URLConnection;->setReadTimeout(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 60
    .line 61
    .line 62
    const-string v1, "GET"

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, Ljava/util/HashMap;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-eqz v1, :cond_1

    .line 84
    .line 85
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Ljava/util/Map$Entry;

    .line 90
    .line 91
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Ljava/lang/String;

    .line 96
    .line 97
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    check-cast v1, Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {v0, v3, v1}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :catchall_0
    move-exception p0

    .line 108
    goto :goto_3

    .line 109
    :cond_1
    invoke-virtual {v0}, Ljava/net/URLConnection;->connect()V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    invoke-virtual {v0}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 117
    .line 118
    .line 119
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 120
    if-eqz v1, :cond_3

    .line 121
    .line 122
    :try_start_2
    new-instance v2, Ljava/io/BufferedReader;

    .line 123
    .line 124
    new-instance v3, Ljava/io/InputStreamReader;

    .line 125
    .line 126
    const-string v4, "UTF-8"

    .line 127
    .line 128
    invoke-direct {v3, v1, v4}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-direct {v2, v3}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 132
    .line 133
    .line 134
    const/16 v3, 0x2000

    .line 135
    .line 136
    new-array v3, v3, [C

    .line 137
    .line 138
    new-instance v4, Ljava/lang/StringBuilder;

    .line 139
    .line 140
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 141
    .line 142
    .line 143
    :goto_1
    invoke-virtual {v2, v3}, Ljava/io/Reader;->read([C)I

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    const/4 v6, -0x1

    .line 148
    if-eq v5, v6, :cond_2

    .line 149
    .line 150
    const/4 v6, 0x0

    .line 151
    invoke-virtual {v4, v3, v6, v5}, Ljava/lang/StringBuilder;->append([CII)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_2
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 159
    goto :goto_2

    .line 160
    :catchall_1
    move-exception p0

    .line 161
    move-object v2, v1

    .line 162
    goto :goto_3

    .line 163
    :cond_3
    :goto_2
    if-eqz v1, :cond_4

    .line 164
    .line 165
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    .line 166
    .line 167
    .line 168
    :cond_4
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 169
    .line 170
    .line 171
    new-instance v0, Lrs/a;

    .line 172
    .line 173
    invoke-direct {v0, p0, v2}, Lrs/a;-><init>(ILjava/lang/String;)V

    .line 174
    .line 175
    .line 176
    return-object v0

    .line 177
    :catchall_2
    move-exception p0

    .line 178
    move-object v0, v2

    .line 179
    :goto_3
    if-eqz v2, :cond_5

    .line 180
    .line 181
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V

    .line 182
    .line 183
    .line 184
    :cond_5
    if-eqz v0, :cond_6

    .line 185
    .line 186
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 187
    .line 188
    .line 189
    :cond_6
    throw p0
.end method

.method public shutdown()V
    .locals 1

    .line 1
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/net/ConnectivityManager;

    .line 4
    .line 5
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ldm0/j;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public t(I)[Landroid/util/Size;
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    const-string v3, "StreamConfigurationMapCompat"

    .line 6
    .line 7
    iget-object v0, v1, Lrn/i;->g:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v4, v0

    .line 10
    check-cast v4, Ljava/util/HashMap;

    .line 11
    .line 12
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v4, v0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v5, 0x0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-virtual {v4, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, [Landroid/util/Size;

    .line 32
    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    return-object v5

    .line 36
    :cond_0
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {v4, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    check-cast v0, [Landroid/util/Size;

    .line 45
    .line 46
    invoke-virtual {v0}, [Landroid/util/Size;->clone()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, [Landroid/util/Size;

    .line 51
    .line 52
    return-object v0

    .line 53
    :cond_1
    :try_start_0
    iget-object v0, v1, Lrn/i;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Lro/f;

    .line 56
    .line 57
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 60
    .line 61
    invoke-virtual {v0, v2}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getOutputSizes(I)[Landroid/util/Size;

    .line 62
    .line 63
    .line 64
    move-result-object v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception v0

    .line 67
    new-instance v6, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v7, "Failed to get output sizes for "

    .line 70
    .line 71
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    invoke-static {v3, v6, v0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    :goto_0
    if-eqz v5, :cond_1a

    .line 85
    .line 86
    array-length v0, v5

    .line 87
    if-nez v0, :cond_2

    .line 88
    .line 89
    goto/16 :goto_6

    .line 90
    .line 91
    :cond_2
    iget-object v0, v1, Lrn/i;->f:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v0, Ly/a;

    .line 94
    .line 95
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    new-instance v1, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-static {v5}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 105
    .line 106
    .line 107
    iget-object v3, v0, Ly/a;->a:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v3, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedOutputSizeQuirk;

    .line 110
    .line 111
    const/4 v5, 0x0

    .line 112
    const/16 v6, 0x2d0

    .line 113
    .line 114
    const/16 v7, 0x438

    .line 115
    .line 116
    const/16 v8, 0x5a0

    .line 117
    .line 118
    const/16 v9, 0x22

    .line 119
    .line 120
    if-nez v3, :cond_3

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_3
    if-ne v2, v9, :cond_4

    .line 124
    .line 125
    const-string v3, "motorola"

    .line 126
    .line 127
    sget-object v10, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 128
    .line 129
    invoke-virtual {v3, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    if-eqz v3, :cond_4

    .line 134
    .line 135
    const-string v3, "moto e5 play"

    .line 136
    .line 137
    sget-object v10, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 138
    .line 139
    invoke-virtual {v3, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 140
    .line 141
    .line 142
    move-result v3

    .line 143
    if-eqz v3, :cond_4

    .line 144
    .line 145
    new-instance v3, Landroid/util/Size;

    .line 146
    .line 147
    invoke-direct {v3, v8, v7}, Landroid/util/Size;-><init>(II)V

    .line 148
    .line 149
    .line 150
    new-instance v10, Landroid/util/Size;

    .line 151
    .line 152
    const/16 v11, 0x3c0

    .line 153
    .line 154
    invoke-direct {v10, v11, v6}, Landroid/util/Size;-><init>(II)V

    .line 155
    .line 156
    .line 157
    filled-new-array {v3, v10}, [Landroid/util/Size;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    goto :goto_1

    .line 162
    :cond_4
    new-array v3, v5, [Landroid/util/Size;

    .line 163
    .line 164
    :goto_1
    array-length v10, v3

    .line 165
    if-lez v10, :cond_5

    .line 166
    .line 167
    invoke-static {v3}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 172
    .line 173
    .line 174
    :cond_5
    :goto_2
    iget-object v0, v0, Ly/a;->b:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v0, Lj51/i;

    .line 177
    .line 178
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 179
    .line 180
    .line 181
    const-class v3, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;

    .line 182
    .line 183
    sget-object v10, Lx/a;->a:Ld01/x;

    .line 184
    .line 185
    invoke-virtual {v10, v3}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    check-cast v3, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;

    .line 190
    .line 191
    if-nez v3, :cond_6

    .line 192
    .line 193
    new-instance v0, Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 196
    .line 197
    .line 198
    goto/16 :goto_4

    .line 199
    .line 200
    :cond_6
    iget-object v0, v0, Lj51/i;->b:Ljava/lang/String;

    .line 201
    .line 202
    sget-object v3, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 203
    .line 204
    const-string v10, "OnePlus"

    .line 205
    .line 206
    invoke-virtual {v10, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 207
    .line 208
    .line 209
    move-result v11

    .line 210
    const/16 v12, 0xc30

    .line 211
    .line 212
    const/16 v13, 0x1040

    .line 213
    .line 214
    const/16 v14, 0xbb8

    .line 215
    .line 216
    const/16 v15, 0xfa0

    .line 217
    .line 218
    const/16 v5, 0x100

    .line 219
    .line 220
    const-string v8, "0"

    .line 221
    .line 222
    if-eqz v11, :cond_8

    .line 223
    .line 224
    const-string v11, "OnePlus6"

    .line 225
    .line 226
    sget-object v7, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 227
    .line 228
    invoke-virtual {v11, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 229
    .line 230
    .line 231
    move-result v7

    .line 232
    if-eqz v7, :cond_8

    .line 233
    .line 234
    new-instance v3, Ljava/util/ArrayList;

    .line 235
    .line 236
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v0, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v0

    .line 243
    if-eqz v0, :cond_7

    .line 244
    .line 245
    if-ne v2, v5, :cond_7

    .line 246
    .line 247
    new-instance v0, Landroid/util/Size;

    .line 248
    .line 249
    invoke-direct {v0, v13, v12}, Landroid/util/Size;-><init>(II)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    new-instance v0, Landroid/util/Size;

    .line 256
    .line 257
    invoke-direct {v0, v15, v14}, Landroid/util/Size;-><init>(II)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    :cond_7
    :goto_3
    move-object v0, v3

    .line 264
    goto/16 :goto_4

    .line 265
    .line 266
    :cond_8
    invoke-virtual {v10, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 267
    .line 268
    .line 269
    move-result v7

    .line 270
    if-eqz v7, :cond_9

    .line 271
    .line 272
    const-string v7, "OnePlus6T"

    .line 273
    .line 274
    sget-object v10, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 275
    .line 276
    invoke-virtual {v7, v10}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    if-eqz v7, :cond_9

    .line 281
    .line 282
    new-instance v3, Ljava/util/ArrayList;

    .line 283
    .line 284
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v0, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    if-eqz v0, :cond_7

    .line 292
    .line 293
    if-ne v2, v5, :cond_7

    .line 294
    .line 295
    new-instance v0, Landroid/util/Size;

    .line 296
    .line 297
    invoke-direct {v0, v13, v12}, Landroid/util/Size;-><init>(II)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    new-instance v0, Landroid/util/Size;

    .line 304
    .line 305
    invoke-direct {v0, v15, v14}, Landroid/util/Size;-><init>(II)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    goto :goto_3

    .line 312
    :cond_9
    const-string v7, "HUAWEI"

    .line 313
    .line 314
    invoke-virtual {v7, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 315
    .line 316
    .line 317
    move-result v7

    .line 318
    const/16 v10, 0x23

    .line 319
    .line 320
    if-eqz v7, :cond_b

    .line 321
    .line 322
    const-string v7, "HWANE"

    .line 323
    .line 324
    sget-object v11, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 325
    .line 326
    invoke-virtual {v7, v11}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 327
    .line 328
    .line 329
    move-result v7

    .line 330
    if-eqz v7, :cond_b

    .line 331
    .line 332
    new-instance v3, Ljava/util/ArrayList;

    .line 333
    .line 334
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v0, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v0

    .line 341
    if-eqz v0, :cond_7

    .line 342
    .line 343
    if-eq v2, v9, :cond_a

    .line 344
    .line 345
    if-eq v2, v10, :cond_a

    .line 346
    .line 347
    goto :goto_3

    .line 348
    :cond_a
    new-instance v0, Landroid/util/Size;

    .line 349
    .line 350
    invoke-direct {v0, v6, v6}, Landroid/util/Size;-><init>(II)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    new-instance v0, Landroid/util/Size;

    .line 357
    .line 358
    const/16 v5, 0x190

    .line 359
    .line 360
    invoke-direct {v0, v5, v5}, Landroid/util/Size;-><init>(II)V

    .line 361
    .line 362
    .line 363
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 364
    .line 365
    .line 366
    goto :goto_3

    .line 367
    :cond_b
    const-string v6, "SAMSUNG"

    .line 368
    .line 369
    invoke-virtual {v6, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 370
    .line 371
    .line 372
    move-result v7

    .line 373
    const-string v11, "1"

    .line 374
    .line 375
    const/16 v14, 0xc10

    .line 376
    .line 377
    const/16 v15, 0x1020

    .line 378
    .line 379
    const/16 v12, 0x912

    .line 380
    .line 381
    const/16 v13, 0xcc0

    .line 382
    .line 383
    if-eqz v7, :cond_f

    .line 384
    .line 385
    const-string v7, "ON7XELTE"

    .line 386
    .line 387
    sget-object v5, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 388
    .line 389
    invoke-virtual {v7, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    if-eqz v5, :cond_f

    .line 394
    .line 395
    new-instance v3, Ljava/util/ArrayList;

    .line 396
    .line 397
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v0, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 401
    .line 402
    .line 403
    move-result v5

    .line 404
    if-eqz v5, :cond_d

    .line 405
    .line 406
    if-eq v2, v9, :cond_c

    .line 407
    .line 408
    if-ne v2, v10, :cond_7

    .line 409
    .line 410
    new-instance v0, Landroid/util/Size;

    .line 411
    .line 412
    invoke-direct {v0, v15, v12}, Landroid/util/Size;-><init>(II)V

    .line 413
    .line 414
    .line 415
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 416
    .line 417
    .line 418
    new-instance v0, Landroid/util/Size;

    .line 419
    .line 420
    invoke-direct {v0, v14, v14}, Landroid/util/Size;-><init>(II)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    new-instance v0, Landroid/util/Size;

    .line 427
    .line 428
    const/16 v5, 0x990

    .line 429
    .line 430
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 434
    .line 435
    .line 436
    new-instance v0, Landroid/util/Size;

    .line 437
    .line 438
    const/16 v5, 0x72c

    .line 439
    .line 440
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 441
    .line 442
    .line 443
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 444
    .line 445
    .line 446
    new-instance v0, Landroid/util/Size;

    .line 447
    .line 448
    const/16 v5, 0x800

    .line 449
    .line 450
    const/16 v6, 0x600

    .line 451
    .line 452
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 456
    .line 457
    .line 458
    new-instance v0, Landroid/util/Size;

    .line 459
    .line 460
    const/16 v6, 0x480

    .line 461
    .line 462
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 463
    .line 464
    .line 465
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 466
    .line 467
    .line 468
    new-instance v0, Landroid/util/Size;

    .line 469
    .line 470
    const/16 v5, 0x438

    .line 471
    .line 472
    const/16 v6, 0x780

    .line 473
    .line 474
    invoke-direct {v0, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 475
    .line 476
    .line 477
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    goto/16 :goto_3

    .line 481
    .line 482
    :cond_c
    new-instance v0, Landroid/util/Size;

    .line 483
    .line 484
    const/16 v5, 0xc18

    .line 485
    .line 486
    invoke-direct {v0, v15, v5}, Landroid/util/Size;-><init>(II)V

    .line 487
    .line 488
    .line 489
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 490
    .line 491
    .line 492
    new-instance v0, Landroid/util/Size;

    .line 493
    .line 494
    invoke-direct {v0, v15, v12}, Landroid/util/Size;-><init>(II)V

    .line 495
    .line 496
    .line 497
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 498
    .line 499
    .line 500
    new-instance v0, Landroid/util/Size;

    .line 501
    .line 502
    invoke-direct {v0, v14, v14}, Landroid/util/Size;-><init>(II)V

    .line 503
    .line 504
    .line 505
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 506
    .line 507
    .line 508
    new-instance v0, Landroid/util/Size;

    .line 509
    .line 510
    const/16 v5, 0x990

    .line 511
    .line 512
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 513
    .line 514
    .line 515
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    new-instance v0, Landroid/util/Size;

    .line 519
    .line 520
    const/16 v5, 0x72c

    .line 521
    .line 522
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 523
    .line 524
    .line 525
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 526
    .line 527
    .line 528
    new-instance v0, Landroid/util/Size;

    .line 529
    .line 530
    const/16 v5, 0x800

    .line 531
    .line 532
    const/16 v6, 0x600

    .line 533
    .line 534
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 535
    .line 536
    .line 537
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 538
    .line 539
    .line 540
    new-instance v0, Landroid/util/Size;

    .line 541
    .line 542
    const/16 v6, 0x480

    .line 543
    .line 544
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 545
    .line 546
    .line 547
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 548
    .line 549
    .line 550
    new-instance v0, Landroid/util/Size;

    .line 551
    .line 552
    const/16 v5, 0x438

    .line 553
    .line 554
    const/16 v6, 0x780

    .line 555
    .line 556
    invoke-direct {v0, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 557
    .line 558
    .line 559
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 560
    .line 561
    .line 562
    goto/16 :goto_3

    .line 563
    .line 564
    :cond_d
    invoke-virtual {v0, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 565
    .line 566
    .line 567
    move-result v0

    .line 568
    if-eqz v0, :cond_7

    .line 569
    .line 570
    if-eq v2, v9, :cond_e

    .line 571
    .line 572
    if-eq v2, v10, :cond_e

    .line 573
    .line 574
    goto/16 :goto_3

    .line 575
    .line 576
    :cond_e
    new-instance v0, Landroid/util/Size;

    .line 577
    .line 578
    const/16 v5, 0x990

    .line 579
    .line 580
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 581
    .line 582
    .line 583
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 584
    .line 585
    .line 586
    new-instance v0, Landroid/util/Size;

    .line 587
    .line 588
    const/16 v6, 0x72c

    .line 589
    .line 590
    invoke-direct {v0, v13, v6}, Landroid/util/Size;-><init>(II)V

    .line 591
    .line 592
    .line 593
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 594
    .line 595
    .line 596
    new-instance v0, Landroid/util/Size;

    .line 597
    .line 598
    invoke-direct {v0, v5, v5}, Landroid/util/Size;-><init>(II)V

    .line 599
    .line 600
    .line 601
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 602
    .line 603
    .line 604
    new-instance v0, Landroid/util/Size;

    .line 605
    .line 606
    const/16 v6, 0x780

    .line 607
    .line 608
    invoke-direct {v0, v6, v6}, Landroid/util/Size;-><init>(II)V

    .line 609
    .line 610
    .line 611
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 612
    .line 613
    .line 614
    new-instance v0, Landroid/util/Size;

    .line 615
    .line 616
    const/16 v5, 0x800

    .line 617
    .line 618
    const/16 v7, 0x600

    .line 619
    .line 620
    invoke-direct {v0, v5, v7}, Landroid/util/Size;-><init>(II)V

    .line 621
    .line 622
    .line 623
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 624
    .line 625
    .line 626
    new-instance v0, Landroid/util/Size;

    .line 627
    .line 628
    const/16 v7, 0x480

    .line 629
    .line 630
    invoke-direct {v0, v5, v7}, Landroid/util/Size;-><init>(II)V

    .line 631
    .line 632
    .line 633
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 634
    .line 635
    .line 636
    new-instance v0, Landroid/util/Size;

    .line 637
    .line 638
    const/16 v5, 0x438

    .line 639
    .line 640
    invoke-direct {v0, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 641
    .line 642
    .line 643
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 644
    .line 645
    .line 646
    goto/16 :goto_3

    .line 647
    .line 648
    :cond_f
    invoke-virtual {v6, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 649
    .line 650
    .line 651
    move-result v5

    .line 652
    if-eqz v5, :cond_13

    .line 653
    .line 654
    const-string v5, "J7XELTE"

    .line 655
    .line 656
    sget-object v6, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 657
    .line 658
    invoke-virtual {v5, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 659
    .line 660
    .line 661
    move-result v5

    .line 662
    if-eqz v5, :cond_13

    .line 663
    .line 664
    new-instance v3, Ljava/util/ArrayList;

    .line 665
    .line 666
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 667
    .line 668
    .line 669
    invoke-virtual {v0, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 670
    .line 671
    .line 672
    move-result v5

    .line 673
    if-eqz v5, :cond_11

    .line 674
    .line 675
    if-eq v2, v9, :cond_10

    .line 676
    .line 677
    if-ne v2, v10, :cond_7

    .line 678
    .line 679
    new-instance v0, Landroid/util/Size;

    .line 680
    .line 681
    const/16 v5, 0x800

    .line 682
    .line 683
    const/16 v6, 0x600

    .line 684
    .line 685
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 686
    .line 687
    .line 688
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 689
    .line 690
    .line 691
    new-instance v0, Landroid/util/Size;

    .line 692
    .line 693
    const/16 v6, 0x480

    .line 694
    .line 695
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 696
    .line 697
    .line 698
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 699
    .line 700
    .line 701
    new-instance v0, Landroid/util/Size;

    .line 702
    .line 703
    const/16 v5, 0x438

    .line 704
    .line 705
    const/16 v6, 0x780

    .line 706
    .line 707
    invoke-direct {v0, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 708
    .line 709
    .line 710
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 711
    .line 712
    .line 713
    goto/16 :goto_3

    .line 714
    .line 715
    :cond_10
    new-instance v0, Landroid/util/Size;

    .line 716
    .line 717
    const/16 v5, 0xc18

    .line 718
    .line 719
    invoke-direct {v0, v15, v5}, Landroid/util/Size;-><init>(II)V

    .line 720
    .line 721
    .line 722
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 723
    .line 724
    .line 725
    new-instance v0, Landroid/util/Size;

    .line 726
    .line 727
    invoke-direct {v0, v15, v12}, Landroid/util/Size;-><init>(II)V

    .line 728
    .line 729
    .line 730
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 731
    .line 732
    .line 733
    new-instance v0, Landroid/util/Size;

    .line 734
    .line 735
    invoke-direct {v0, v14, v14}, Landroid/util/Size;-><init>(II)V

    .line 736
    .line 737
    .line 738
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 739
    .line 740
    .line 741
    new-instance v0, Landroid/util/Size;

    .line 742
    .line 743
    const/16 v5, 0x990

    .line 744
    .line 745
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 746
    .line 747
    .line 748
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 749
    .line 750
    .line 751
    new-instance v0, Landroid/util/Size;

    .line 752
    .line 753
    const/16 v5, 0x72c

    .line 754
    .line 755
    invoke-direct {v0, v13, v5}, Landroid/util/Size;-><init>(II)V

    .line 756
    .line 757
    .line 758
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 759
    .line 760
    .line 761
    new-instance v0, Landroid/util/Size;

    .line 762
    .line 763
    const/16 v5, 0x800

    .line 764
    .line 765
    const/16 v6, 0x600

    .line 766
    .line 767
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 768
    .line 769
    .line 770
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 771
    .line 772
    .line 773
    new-instance v0, Landroid/util/Size;

    .line 774
    .line 775
    const/16 v6, 0x480

    .line 776
    .line 777
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 778
    .line 779
    .line 780
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 781
    .line 782
    .line 783
    new-instance v0, Landroid/util/Size;

    .line 784
    .line 785
    const/16 v5, 0x438

    .line 786
    .line 787
    const/16 v6, 0x780

    .line 788
    .line 789
    invoke-direct {v0, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 790
    .line 791
    .line 792
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 793
    .line 794
    .line 795
    goto/16 :goto_3

    .line 796
    .line 797
    :cond_11
    invoke-virtual {v0, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 798
    .line 799
    .line 800
    move-result v0

    .line 801
    if-eqz v0, :cond_7

    .line 802
    .line 803
    if-eq v2, v9, :cond_12

    .line 804
    .line 805
    if-eq v2, v10, :cond_12

    .line 806
    .line 807
    goto/16 :goto_3

    .line 808
    .line 809
    :cond_12
    new-instance v0, Landroid/util/Size;

    .line 810
    .line 811
    const/16 v5, 0xa10

    .line 812
    .line 813
    const/16 v6, 0x78c

    .line 814
    .line 815
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 816
    .line 817
    .line 818
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 819
    .line 820
    .line 821
    new-instance v0, Landroid/util/Size;

    .line 822
    .line 823
    const/16 v5, 0xa00

    .line 824
    .line 825
    const/16 v6, 0x5a0

    .line 826
    .line 827
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 828
    .line 829
    .line 830
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 831
    .line 832
    .line 833
    new-instance v0, Landroid/util/Size;

    .line 834
    .line 835
    const/16 v6, 0x780

    .line 836
    .line 837
    invoke-direct {v0, v6, v6}, Landroid/util/Size;-><init>(II)V

    .line 838
    .line 839
    .line 840
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 841
    .line 842
    .line 843
    new-instance v0, Landroid/util/Size;

    .line 844
    .line 845
    const/16 v5, 0x800

    .line 846
    .line 847
    const/16 v7, 0x600

    .line 848
    .line 849
    invoke-direct {v0, v5, v7}, Landroid/util/Size;-><init>(II)V

    .line 850
    .line 851
    .line 852
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 853
    .line 854
    .line 855
    new-instance v0, Landroid/util/Size;

    .line 856
    .line 857
    const/16 v7, 0x480

    .line 858
    .line 859
    invoke-direct {v0, v5, v7}, Landroid/util/Size;-><init>(II)V

    .line 860
    .line 861
    .line 862
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 863
    .line 864
    .line 865
    new-instance v0, Landroid/util/Size;

    .line 866
    .line 867
    const/16 v5, 0x438

    .line 868
    .line 869
    invoke-direct {v0, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 870
    .line 871
    .line 872
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 873
    .line 874
    .line 875
    goto/16 :goto_3

    .line 876
    .line 877
    :cond_13
    const-string v5, "REDMI"

    .line 878
    .line 879
    invoke-virtual {v5, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 880
    .line 881
    .line 882
    move-result v3

    .line 883
    if-eqz v3, :cond_14

    .line 884
    .line 885
    const-string v3, "joyeuse"

    .line 886
    .line 887
    sget-object v5, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 888
    .line 889
    invoke-virtual {v3, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 890
    .line 891
    .line 892
    move-result v3

    .line 893
    if-eqz v3, :cond_14

    .line 894
    .line 895
    new-instance v3, Ljava/util/ArrayList;

    .line 896
    .line 897
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 898
    .line 899
    .line 900
    invoke-virtual {v0, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 901
    .line 902
    .line 903
    move-result v0

    .line 904
    if-eqz v0, :cond_7

    .line 905
    .line 906
    const/16 v0, 0x100

    .line 907
    .line 908
    if-ne v2, v0, :cond_7

    .line 909
    .line 910
    new-instance v0, Landroid/util/Size;

    .line 911
    .line 912
    const/16 v5, 0x2440

    .line 913
    .line 914
    const/16 v6, 0x1b20

    .line 915
    .line 916
    invoke-direct {v0, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 917
    .line 918
    .line 919
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 920
    .line 921
    .line 922
    goto/16 :goto_3

    .line 923
    .line 924
    :cond_14
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;->c()Z

    .line 925
    .line 926
    .line 927
    move-result v0

    .line 928
    const/16 v3, 0x960

    .line 929
    .line 930
    const/16 v5, 0xc80

    .line 931
    .line 932
    if-eqz v0, :cond_15

    .line 933
    .line 934
    new-instance v0, Ljava/util/ArrayList;

    .line 935
    .line 936
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 937
    .line 938
    .line 939
    if-ne v2, v10, :cond_17

    .line 940
    .line 941
    new-instance v6, Landroid/util/Size;

    .line 942
    .line 943
    const/16 v7, 0xf00

    .line 944
    .line 945
    const/16 v8, 0x870

    .line 946
    .line 947
    invoke-direct {v6, v7, v8}, Landroid/util/Size;-><init>(II)V

    .line 948
    .line 949
    .line 950
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 951
    .line 952
    .line 953
    new-instance v6, Landroid/util/Size;

    .line 954
    .line 955
    const/16 v7, 0x990

    .line 956
    .line 957
    invoke-direct {v6, v13, v7}, Landroid/util/Size;-><init>(II)V

    .line 958
    .line 959
    .line 960
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 961
    .line 962
    .line 963
    new-instance v6, Landroid/util/Size;

    .line 964
    .line 965
    invoke-direct {v6, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 966
    .line 967
    .line 968
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 969
    .line 970
    .line 971
    new-instance v3, Landroid/util/Size;

    .line 972
    .line 973
    const/16 v5, 0xa80

    .line 974
    .line 975
    const/16 v6, 0x5e8

    .line 976
    .line 977
    invoke-direct {v3, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 978
    .line 979
    .line 980
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 981
    .line 982
    .line 983
    new-instance v3, Landroid/util/Size;

    .line 984
    .line 985
    const/16 v5, 0x798

    .line 986
    .line 987
    const/16 v6, 0xa20

    .line 988
    .line 989
    invoke-direct {v3, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 990
    .line 991
    .line 992
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 993
    .line 994
    .line 995
    new-instance v3, Landroid/util/Size;

    .line 996
    .line 997
    const/16 v5, 0x794

    .line 998
    .line 999
    invoke-direct {v3, v6, v5}, Landroid/util/Size;-><init>(II)V

    .line 1000
    .line 1001
    .line 1002
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1003
    .line 1004
    .line 1005
    new-instance v3, Landroid/util/Size;

    .line 1006
    .line 1007
    const/16 v5, 0x780

    .line 1008
    .line 1009
    const/16 v6, 0x5a0

    .line 1010
    .line 1011
    invoke-direct {v3, v5, v6}, Landroid/util/Size;-><init>(II)V

    .line 1012
    .line 1013
    .line 1014
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1015
    .line 1016
    .line 1017
    goto :goto_4

    .line 1018
    :cond_15
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExcludedSupportedSizesQuirk;->b()Z

    .line 1019
    .line 1020
    .line 1021
    move-result v0

    .line 1022
    if-eqz v0, :cond_16

    .line 1023
    .line 1024
    new-instance v0, Ljava/util/ArrayList;

    .line 1025
    .line 1026
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1027
    .line 1028
    .line 1029
    if-ne v2, v10, :cond_17

    .line 1030
    .line 1031
    new-instance v6, Landroid/util/Size;

    .line 1032
    .line 1033
    const/16 v7, 0xfc0

    .line 1034
    .line 1035
    const/16 v8, 0xbd0

    .line 1036
    .line 1037
    invoke-direct {v6, v7, v8}, Landroid/util/Size;-><init>(II)V

    .line 1038
    .line 1039
    .line 1040
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1041
    .line 1042
    .line 1043
    new-instance v6, Landroid/util/Size;

    .line 1044
    .line 1045
    const/16 v7, 0xbb8

    .line 1046
    .line 1047
    const/16 v9, 0xfa0

    .line 1048
    .line 1049
    invoke-direct {v6, v9, v7}, Landroid/util/Size;-><init>(II)V

    .line 1050
    .line 1051
    .line 1052
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1053
    .line 1054
    .line 1055
    new-instance v6, Landroid/util/Size;

    .line 1056
    .line 1057
    const/16 v7, 0x990

    .line 1058
    .line 1059
    invoke-direct {v6, v13, v7}, Landroid/util/Size;-><init>(II)V

    .line 1060
    .line 1061
    .line 1062
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1063
    .line 1064
    .line 1065
    new-instance v6, Landroid/util/Size;

    .line 1066
    .line 1067
    invoke-direct {v6, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 1068
    .line 1069
    .line 1070
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1071
    .line 1072
    .line 1073
    new-instance v3, Landroid/util/Size;

    .line 1074
    .line 1075
    invoke-direct {v3, v8, v8}, Landroid/util/Size;-><init>(II)V

    .line 1076
    .line 1077
    .line 1078
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1079
    .line 1080
    .line 1081
    new-instance v3, Landroid/util/Size;

    .line 1082
    .line 1083
    const/16 v5, 0xba0

    .line 1084
    .line 1085
    invoke-direct {v3, v5, v5}, Landroid/util/Size;-><init>(II)V

    .line 1086
    .line 1087
    .line 1088
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1089
    .line 1090
    .line 1091
    new-instance v3, Landroid/util/Size;

    .line 1092
    .line 1093
    const/16 v5, 0x990

    .line 1094
    .line 1095
    invoke-direct {v3, v5, v5}, Landroid/util/Size;-><init>(II)V

    .line 1096
    .line 1097
    .line 1098
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1099
    .line 1100
    .line 1101
    goto :goto_4

    .line 1102
    :cond_16
    const-string v0, "ExcludedSupportedSizesQuirk"

    .line 1103
    .line 1104
    const-string v3, "Cannot retrieve list of supported sizes to exclude on this device."

    .line 1105
    .line 1106
    invoke-static {v0, v3}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 1107
    .line 1108
    .line 1109
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 1110
    .line 1111
    :cond_17
    :goto_4
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 1112
    .line 1113
    .line 1114
    move-result v3

    .line 1115
    if-eqz v3, :cond_18

    .line 1116
    .line 1117
    goto :goto_5

    .line 1118
    :cond_18
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 1119
    .line 1120
    .line 1121
    :goto_5
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1122
    .line 1123
    .line 1124
    move-result v0

    .line 1125
    if-eqz v0, :cond_19

    .line 1126
    .line 1127
    const-string v0, "OutputSizesCorrector"

    .line 1128
    .line 1129
    const-string v3, "Sizes array becomes empty after excluding problematic output sizes."

    .line 1130
    .line 1131
    invoke-static {v0, v3}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 1132
    .line 1133
    .line 1134
    :cond_19
    const/4 v0, 0x0

    .line 1135
    new-array v0, v0, [Landroid/util/Size;

    .line 1136
    .line 1137
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1138
    .line 1139
    .line 1140
    move-result-object v0

    .line 1141
    check-cast v0, [Landroid/util/Size;

    .line 1142
    .line 1143
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v1

    .line 1147
    invoke-virtual {v4, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1148
    .line 1149
    .line 1150
    invoke-virtual {v0}, [Landroid/util/Size;->clone()Ljava/lang/Object;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v0

    .line 1154
    check-cast v0, [Landroid/util/Size;

    .line 1155
    .line 1156
    return-object v0

    .line 1157
    :cond_1a
    :goto_6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1158
    .line 1159
    const-string v1, "Retrieved output sizes array is null or empty for format "

    .line 1160
    .line 1161
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1162
    .line 1163
    .line 1164
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1165
    .line 1166
    .line 1167
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v0

    .line 1171
    invoke-static {v3, v0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 1172
    .line 1173
    .line 1174
    return-object v5
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lrn/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Ljava/lang/String;

    .line 18
    .line 19
    new-instance v2, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v3, "NavDeepLinkRequest{"

    .line 22
    .line 23
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Landroid/net/Uri;

    .line 29
    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    const-string v3, " uri="

    .line 33
    .line 34
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    :cond_0
    if-eqz v1, :cond_1

    .line 45
    .line 46
    const-string p0, " action="

    .line 47
    .line 48
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    :cond_1
    if-eqz v0, :cond_2

    .line 55
    .line 56
    const-string p0, " mimetype="

    .line 57
    .line 58
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    :cond_2
    const-string p0, " }"

    .line 65
    .line 66
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    const-string v0, "toString(...)"

    .line 74
    .line 75
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x19
        :pswitch_0
    .end packed-switch
.end method

.method public u(Ljava/lang/CharSequence;IILs6/t;)Z
    .locals 6

    .line 1
    iget v0, p4, Ls6/t;->c:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x3

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x1

    .line 8
    if-nez v0, :cond_4

    .line 9
    .line 10
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ls6/e;

    .line 13
    .line 14
    invoke-virtual {p4}, Ls6/t;->b()Lt6/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/16 v4, 0x8

    .line 19
    .line 20
    invoke-virtual {v0, v4}, Ld6/h0;->a(I)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    iget-object v5, v0, Ld6/h0;->g:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v5, Ljava/nio/ByteBuffer;

    .line 29
    .line 30
    iget v0, v0, Ld6/h0;->d:I

    .line 31
    .line 32
    add-int/2addr v4, v0

    .line 33
    invoke-virtual {v5, v4}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 34
    .line 35
    .line 36
    :cond_0
    check-cast p0, Ls6/c;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    sget-object v0, Ls6/c;->b:Ljava/lang/ThreadLocal;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    if-nez v4, :cond_1

    .line 48
    .line 49
    new-instance v4, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, v4}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    check-cast v0, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 64
    .line 65
    .line 66
    :goto_0
    if-ge p2, p3, :cond_2

    .line 67
    .line 68
    invoke-interface {p1, p2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    add-int/lit8 p2, p2, 0x1

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    iget-object p0, p0, Ls6/c;->a:Landroid/text/TextPaint;

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    sget p2, Ls5/c;->a:I

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Landroid/graphics/Paint;->hasGlyph(Ljava/lang/String;)Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    iget p1, p4, Ls6/t;->c:I

    .line 91
    .line 92
    and-int/lit8 p1, p1, 0x4

    .line 93
    .line 94
    if-eqz p0, :cond_3

    .line 95
    .line 96
    or-int/lit8 p0, p1, 0x2

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_3
    or-int/lit8 p0, p1, 0x1

    .line 100
    .line 101
    :goto_1
    iput p0, p4, Ls6/t;->c:I

    .line 102
    .line 103
    :cond_4
    iget p0, p4, Ls6/t;->c:I

    .line 104
    .line 105
    and-int/lit8 p0, p0, 0x3

    .line 106
    .line 107
    if-ne p0, v1, :cond_5

    .line 108
    .line 109
    return v3

    .line 110
    :cond_5
    return v2
.end method

.method public v(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public w()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt1/j0;

    .line 4
    .line 5
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lv3/y1;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x1

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lt1/j0;

    .line 19
    .line 20
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lv3/y1;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    iget-object p0, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lt1/j0;

    .line 33
    .line 34
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lv3/y1;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_0

    .line 43
    .line 44
    move p0, v1

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 p0, 0x0

    .line 47
    :goto_0
    xor-int/2addr p0, v1

    .line 48
    return p0
.end method

.method public x(Ljava/lang/CharSequence;IIIZLs6/l;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move/from16 v3, p4

    .line 8
    .line 9
    move-object/from16 v4, p6

    .line 10
    .line 11
    new-instance v5, Ls6/n;

    .line 12
    .line 13
    iget-object v6, v0, Lrn/i;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v6, Lcom/google/firebase/messaging/w;

    .line 16
    .line 17
    iget-object v6, v6, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v6, Ls6/q;

    .line 20
    .line 21
    invoke-direct {v5, v6}, Ls6/n;-><init>(Ls6/q;)V

    .line 22
    .line 23
    .line 24
    invoke-static/range {p1 .. p2}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v8, 0x1

    .line 30
    move v9, v6

    .line 31
    move v10, v7

    .line 32
    move v11, v8

    .line 33
    move/from16 v6, p2

    .line 34
    .line 35
    :cond_0
    :goto_0
    move v7, v6

    .line 36
    :goto_1
    const/4 v12, 0x2

    .line 37
    if-ge v6, v2, :cond_f

    .line 38
    .line 39
    if-ge v10, v3, :cond_f

    .line 40
    .line 41
    if-eqz v11, :cond_f

    .line 42
    .line 43
    iget-object v13, v5, Ls6/n;->c:Ls6/q;

    .line 44
    .line 45
    iget-object v13, v13, Ls6/q;->a:Landroid/util/SparseArray;

    .line 46
    .line 47
    if-nez v13, :cond_1

    .line 48
    .line 49
    const/4 v13, 0x0

    .line 50
    goto :goto_2

    .line 51
    :cond_1
    invoke-virtual {v13, v9}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v13

    .line 55
    check-cast v13, Ls6/q;

    .line 56
    .line 57
    :goto_2
    iget v14, v5, Ls6/n;->a:I

    .line 58
    .line 59
    const/4 v15, 0x3

    .line 60
    if-eq v14, v12, :cond_3

    .line 61
    .line 62
    if-nez v13, :cond_2

    .line 63
    .line 64
    invoke-virtual {v5}, Ls6/n;->a()V

    .line 65
    .line 66
    .line 67
    :goto_3
    move v13, v8

    .line 68
    goto :goto_6

    .line 69
    :cond_2
    iput v12, v5, Ls6/n;->a:I

    .line 70
    .line 71
    iput-object v13, v5, Ls6/n;->c:Ls6/q;

    .line 72
    .line 73
    iput v8, v5, Ls6/n;->f:I

    .line 74
    .line 75
    :goto_4
    move v13, v12

    .line 76
    goto :goto_6

    .line 77
    :cond_3
    if-eqz v13, :cond_4

    .line 78
    .line 79
    iput-object v13, v5, Ls6/n;->c:Ls6/q;

    .line 80
    .line 81
    iget v13, v5, Ls6/n;->f:I

    .line 82
    .line 83
    add-int/2addr v13, v8

    .line 84
    iput v13, v5, Ls6/n;->f:I

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_4
    const v13, 0xfe0e

    .line 88
    .line 89
    .line 90
    if-ne v9, v13, :cond_5

    .line 91
    .line 92
    invoke-virtual {v5}, Ls6/n;->a()V

    .line 93
    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_5
    const v13, 0xfe0f

    .line 97
    .line 98
    .line 99
    if-ne v9, v13, :cond_6

    .line 100
    .line 101
    goto :goto_4

    .line 102
    :cond_6
    iget-object v13, v5, Ls6/n;->c:Ls6/q;

    .line 103
    .line 104
    iget-object v14, v13, Ls6/q;->b:Ls6/t;

    .line 105
    .line 106
    if-eqz v14, :cond_9

    .line 107
    .line 108
    iget v14, v5, Ls6/n;->f:I

    .line 109
    .line 110
    if-ne v14, v8, :cond_8

    .line 111
    .line 112
    invoke-virtual {v5}, Ls6/n;->b()Z

    .line 113
    .line 114
    .line 115
    move-result v13

    .line 116
    if-eqz v13, :cond_7

    .line 117
    .line 118
    iget-object v13, v5, Ls6/n;->c:Ls6/q;

    .line 119
    .line 120
    iput-object v13, v5, Ls6/n;->d:Ls6/q;

    .line 121
    .line 122
    invoke-virtual {v5}, Ls6/n;->a()V

    .line 123
    .line 124
    .line 125
    :goto_5
    move v13, v15

    .line 126
    goto :goto_6

    .line 127
    :cond_7
    invoke-virtual {v5}, Ls6/n;->a()V

    .line 128
    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_8
    iput-object v13, v5, Ls6/n;->d:Ls6/q;

    .line 132
    .line 133
    invoke-virtual {v5}, Ls6/n;->a()V

    .line 134
    .line 135
    .line 136
    goto :goto_5

    .line 137
    :cond_9
    invoke-virtual {v5}, Ls6/n;->a()V

    .line 138
    .line 139
    .line 140
    goto :goto_3

    .line 141
    :goto_6
    iput v9, v5, Ls6/n;->e:I

    .line 142
    .line 143
    if-eq v13, v8, :cond_e

    .line 144
    .line 145
    if-eq v13, v12, :cond_c

    .line 146
    .line 147
    if-eq v13, v15, :cond_a

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_a
    if-nez p5, :cond_b

    .line 151
    .line 152
    iget-object v12, v5, Ls6/n;->d:Ls6/q;

    .line 153
    .line 154
    iget-object v12, v12, Ls6/q;->b:Ls6/t;

    .line 155
    .line 156
    invoke-virtual {v0, v1, v7, v6, v12}, Lrn/i;->u(Ljava/lang/CharSequence;IILs6/t;)Z

    .line 157
    .line 158
    .line 159
    move-result v12

    .line 160
    if-nez v12, :cond_0

    .line 161
    .line 162
    :cond_b
    iget-object v11, v5, Ls6/n;->d:Ls6/q;

    .line 163
    .line 164
    iget-object v11, v11, Ls6/q;->b:Ls6/t;

    .line 165
    .line 166
    invoke-interface {v4, v1, v7, v6, v11}, Ls6/l;->f(Ljava/lang/CharSequence;IILs6/t;)Z

    .line 167
    .line 168
    .line 169
    move-result v11

    .line 170
    add-int/lit8 v10, v10, 0x1

    .line 171
    .line 172
    goto/16 :goto_0

    .line 173
    .line 174
    :cond_c
    invoke-static {v9}, Ljava/lang/Character;->charCount(I)I

    .line 175
    .line 176
    .line 177
    move-result v12

    .line 178
    add-int/2addr v12, v6

    .line 179
    if-ge v12, v2, :cond_d

    .line 180
    .line 181
    invoke-static {v1, v12}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 182
    .line 183
    .line 184
    move-result v6

    .line 185
    move v9, v6

    .line 186
    :cond_d
    move v6, v12

    .line 187
    goto/16 :goto_1

    .line 188
    .line 189
    :cond_e
    invoke-static {v1, v7}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 190
    .line 191
    .line 192
    move-result v6

    .line 193
    invoke-static {v6}, Ljava/lang/Character;->charCount(I)I

    .line 194
    .line 195
    .line 196
    move-result v6

    .line 197
    add-int/2addr v6, v7

    .line 198
    if-ge v6, v2, :cond_0

    .line 199
    .line 200
    invoke-static {v1, v6}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 201
    .line 202
    .line 203
    move-result v7

    .line 204
    move v9, v7

    .line 205
    goto/16 :goto_0

    .line 206
    .line 207
    :cond_f
    iget v2, v5, Ls6/n;->a:I

    .line 208
    .line 209
    if-ne v2, v12, :cond_12

    .line 210
    .line 211
    iget-object v2, v5, Ls6/n;->c:Ls6/q;

    .line 212
    .line 213
    iget-object v2, v2, Ls6/q;->b:Ls6/t;

    .line 214
    .line 215
    if-eqz v2, :cond_12

    .line 216
    .line 217
    iget v2, v5, Ls6/n;->f:I

    .line 218
    .line 219
    if-gt v2, v8, :cond_10

    .line 220
    .line 221
    invoke-virtual {v5}, Ls6/n;->b()Z

    .line 222
    .line 223
    .line 224
    move-result v2

    .line 225
    if-eqz v2, :cond_12

    .line 226
    .line 227
    :cond_10
    if-ge v10, v3, :cond_12

    .line 228
    .line 229
    if-eqz v11, :cond_12

    .line 230
    .line 231
    if-nez p5, :cond_11

    .line 232
    .line 233
    iget-object v2, v5, Ls6/n;->c:Ls6/q;

    .line 234
    .line 235
    iget-object v2, v2, Ls6/q;->b:Ls6/t;

    .line 236
    .line 237
    invoke-virtual {v0, v1, v7, v6, v2}, Lrn/i;->u(Ljava/lang/CharSequence;IILs6/t;)Z

    .line 238
    .line 239
    .line 240
    move-result v0

    .line 241
    if-nez v0, :cond_12

    .line 242
    .line 243
    :cond_11
    iget-object v0, v5, Ls6/n;->c:Ls6/q;

    .line 244
    .line 245
    iget-object v0, v0, Ls6/q;->b:Ls6/t;

    .line 246
    .line 247
    invoke-interface {v4, v1, v7, v6, v0}, Ls6/l;->f(Ljava/lang/CharSequence;IILs6/t;)Z

    .line 248
    .line 249
    .line 250
    :cond_12
    invoke-interface {v4}, Ls6/l;->u()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    return-object v0
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 5

    .line 1
    iget p1, p0, Lrn/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lrn/i;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lw0/c;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-object v0, p1, Lw0/c;->e:Lk0/d;

    .line 12
    .line 13
    iget-object p1, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v1, Lh0/m;

    .line 38
    .line 39
    iget-object v2, p0, Lrn/i;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v2, Lh0/z;

    .line 42
    .line 43
    check-cast v2, Lh0/z;

    .line 44
    .line 45
    invoke-interface {v2, v1}, Lh0/z;->p(Lh0/m;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    .line 50
    .line 51
    .line 52
    :cond_1
    return-void

    .line 53
    :pswitch_0
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lcom/google/android/material/datepicker/d;

    .line 56
    .line 57
    new-instance p1, Lm8/o;

    .line 58
    .line 59
    const/16 v0, 0x13

    .line 60
    .line 61
    invoke-direct {p1, p0, v0}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    invoke-static {}, Llp/k1;->c()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    const/4 v1, 0x1

    .line 69
    if-eqz v0, :cond_2

    .line 70
    .line 71
    invoke-virtual {p1}, Lm8/o;->run()V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
    new-instance v0, Ljava/util/concurrent/CountDownLatch;

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 78
    .line 79
    .line 80
    new-instance v2, Landroid/os/Handler;

    .line 81
    .line 82
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-direct {v2, v3}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 87
    .line 88
    .line 89
    new-instance v3, Lh0/h0;

    .line 90
    .line 91
    const/16 v4, 0x9

    .line 92
    .line 93
    invoke-direct {v3, v4, p1, v0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    const-string v2, "Unable to post to main thread"

    .line 101
    .line 102
    invoke-static {v2, p1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 103
    .line 104
    .line 105
    :try_start_0
    sget-object p1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 106
    .line 107
    const-wide/16 v2, 0x7530

    .line 108
    .line 109
    invoke-virtual {v0, v2, v3, p1}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z

    .line 110
    .line 111
    .line 112
    move-result p1
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 113
    if-eqz p1, :cond_7

    .line 114
    .line 115
    :goto_1
    iget-object p1, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p1, Lb0/u;

    .line 118
    .line 119
    if-eqz p1, :cond_6

    .line 120
    .line 121
    iget-object v0, p1, Lb0/u;->b:Ljava/lang/Object;

    .line 122
    .line 123
    monitor-enter v0

    .line 124
    :try_start_1
    iget-object v2, p1, Lb0/u;->e:Landroid/os/Handler;

    .line 125
    .line 126
    const-string v3, "retry_token"

    .line 127
    .line 128
    invoke-virtual {v2, v3}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iget v2, p1, Lb0/u;->o:I

    .line 132
    .line 133
    invoke-static {v2}, Lu/w;->o(I)I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    const/4 v3, 0x5

    .line 138
    if-eqz v2, :cond_5

    .line 139
    .line 140
    if-eq v2, v1, :cond_4

    .line 141
    .line 142
    const/4 v1, 0x2

    .line 143
    if-eq v2, v1, :cond_3

    .line 144
    .line 145
    const/4 v1, 0x3

    .line 146
    if-eq v2, v1, :cond_3

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_3
    iput v3, p1, Lb0/u;->o:I

    .line 150
    .line 151
    iget-object v1, p1, Lb0/u;->q:Ljava/lang/Integer;

    .line 152
    .line 153
    invoke-static {v1}, Lb0/u;->a(Ljava/lang/Integer;)V

    .line 154
    .line 155
    .line 156
    new-instance v1, La8/t;

    .line 157
    .line 158
    const/4 v2, 0x7

    .line 159
    invoke-direct {v1, p1, v2}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 160
    .line 161
    .line 162
    invoke-static {v1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    iput-object v1, p1, Lb0/u;->p:Lcom/google/common/util/concurrent/ListenableFuture;

    .line 167
    .line 168
    :goto_2
    iget-object p1, p1, Lb0/u;->p:Lcom/google/common/util/concurrent/ListenableFuture;

    .line 169
    .line 170
    monitor-exit v0

    .line 171
    goto :goto_4

    .line 172
    :catchall_0
    move-exception p0

    .line 173
    goto :goto_3

    .line 174
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 175
    .line 176
    const-string p1, "CameraX could not be shutdown when it is initializing."

    .line 177
    .line 178
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    throw p0

    .line 182
    :cond_5
    iput v3, p1, Lb0/u;->o:I

    .line 183
    .line 184
    sget-object p1, Lk0/j;->f:Lk0/j;

    .line 185
    .line 186
    monitor-exit v0

    .line 187
    goto :goto_4

    .line 188
    :goto_3
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 189
    throw p0

    .line 190
    :cond_6
    sget-object p1, Lk0/j;->f:Lk0/j;

    .line 191
    .line 192
    :goto_4
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 196
    .line 197
    monitor-enter v0

    .line 198
    const/4 v1, 0x0

    .line 199
    :try_start_2
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 200
    .line 201
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 202
    .line 203
    iget-object p1, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast p1, Ljava/util/HashMap;

    .line 206
    .line 207
    invoke-virtual {p1}, Ljava/util/HashMap;->clear()V

    .line 208
    .line 209
    .line 210
    iget-object p1, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast p1, Ljava/util/HashSet;

    .line 213
    .line 214
    invoke-virtual {p1}, Ljava/util/HashSet;->clear()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 215
    .line 216
    .line 217
    monitor-exit v0

    .line 218
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 219
    .line 220
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 221
    .line 222
    return-void

    .line 223
    :catchall_1
    move-exception p0

    .line 224
    monitor-exit v0

    .line 225
    throw p0

    .line 226
    :cond_7
    :try_start_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 227
    .line 228
    const-string p1, "Timeout to wait main thread execution"

    .line 229
    .line 230
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    throw p0
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0

    .line 234
    :catch_0
    move-exception p0

    .line 235
    new-instance p1, La8/r0;

    .line 236
    .line 237
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 238
    .line 239
    .line 240
    throw p1

    .line 241
    :pswitch_data_0
    .packed-switch 0xd
        :pswitch_0
    .end packed-switch
.end method

.method public z(Lrn/j;IZ)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lrn/i;->g:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Lxn/a;

    .line 10
    .line 11
    new-instance v4, Landroid/content/ComponentName;

    .line 12
    .line 13
    iget-object v5, v0, Lrn/i;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v5, Landroid/content/Context;

    .line 16
    .line 17
    const-class v6, Lcom/google/android/datatransport/runtime/scheduling/jobscheduling/JobInfoSchedulerService;

    .line 18
    .line 19
    invoke-direct {v4, v5, v6}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 20
    .line 21
    .line 22
    const-string v6, "jobscheduler"

    .line 23
    .line 24
    invoke-virtual {v5, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v6

    .line 28
    check-cast v6, Landroid/app/job/JobScheduler;

    .line 29
    .line 30
    new-instance v7, Ljava/util/zip/Adler32;

    .line 31
    .line 32
    invoke-direct {v7}, Ljava/util/zip/Adler32;-><init>()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v5}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    const-string v8, "UTF-8"

    .line 40
    .line 41
    invoke-static {v8}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 42
    .line 43
    .line 44
    move-result-object v9

    .line 45
    invoke-virtual {v5, v9}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    invoke-virtual {v7, v5}, Ljava/util/zip/Adler32;->update([B)V

    .line 50
    .line 51
    .line 52
    iget-object v5, v1, Lrn/j;->a:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v9, v1, Lrn/j;->a:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v8}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    invoke-virtual {v5, v8}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    invoke-virtual {v7, v5}, Ljava/util/zip/Adler32;->update([B)V

    .line 65
    .line 66
    .line 67
    const/4 v5, 0x4

    .line 68
    invoke-static {v5}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    iget-object v8, v1, Lrn/j;->c:Lon/d;

    .line 73
    .line 74
    invoke-static {v8}, Lbo/a;->a(Lon/d;)I

    .line 75
    .line 76
    .line 77
    move-result v10

    .line 78
    invoke-virtual {v5, v10}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->array()[B

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    invoke-virtual {v7, v5}, Ljava/util/zip/Adler32;->update([B)V

    .line 87
    .line 88
    .line 89
    iget-object v5, v1, Lrn/j;->b:[B

    .line 90
    .line 91
    if-eqz v5, :cond_0

    .line 92
    .line 93
    invoke-virtual {v7, v5}, Ljava/util/zip/Adler32;->update([B)V

    .line 94
    .line 95
    .line 96
    :cond_0
    invoke-virtual {v7}, Ljava/util/zip/Adler32;->getValue()J

    .line 97
    .line 98
    .line 99
    move-result-wide v10

    .line 100
    long-to-int v7, v10

    .line 101
    const-string v10, "JobInfoScheduler"

    .line 102
    .line 103
    const-string v11, "attemptNumber"

    .line 104
    .line 105
    if-nez p3, :cond_2

    .line 106
    .line 107
    invoke-virtual {v6}, Landroid/app/job/JobScheduler;->getAllPendingJobs()Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object v12

    .line 111
    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 112
    .line 113
    .line 114
    move-result-object v12

    .line 115
    :cond_1
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 116
    .line 117
    .line 118
    move-result v13

    .line 119
    if-eqz v13, :cond_2

    .line 120
    .line 121
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v13

    .line 125
    check-cast v13, Landroid/app/job/JobInfo;

    .line 126
    .line 127
    invoke-virtual {v13}, Landroid/app/job/JobInfo;->getExtras()Landroid/os/PersistableBundle;

    .line 128
    .line 129
    .line 130
    move-result-object v14

    .line 131
    invoke-virtual {v14, v11}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 132
    .line 133
    .line 134
    move-result v14

    .line 135
    invoke-virtual {v13}, Landroid/app/job/JobInfo;->getId()I

    .line 136
    .line 137
    .line 138
    move-result v13

    .line 139
    if-ne v13, v7, :cond_1

    .line 140
    .line 141
    if-lt v14, v2, :cond_2

    .line 142
    .line 143
    const-string v0, "Upload for context %s is already scheduled. Returning..."

    .line 144
    .line 145
    invoke-static {v1, v10, v0}, Llp/wb;->b(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_2
    iget-object v0, v0, Lrn/i;->f:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v0, Lyn/d;

    .line 152
    .line 153
    check-cast v0, Lyn/h;

    .line 154
    .line 155
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-static {v8}, Lbo/a;->a(Lon/d;)I

    .line 160
    .line 161
    .line 162
    move-result v12

    .line 163
    invoke-static {v12}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v12

    .line 167
    filled-new-array {v9, v12}, [Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v12

    .line 171
    const-string v13, "SELECT next_request_ms FROM transport_contexts WHERE backend_name = ? and priority = ?"

    .line 172
    .line 173
    invoke-virtual {v0, v13, v12}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 174
    .line 175
    .line 176
    move-result-object v12

    .line 177
    :try_start_0
    invoke-interface {v12}, Landroid/database/Cursor;->moveToNext()Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    const/4 v13, 0x0

    .line 182
    if-eqz v0, :cond_3

    .line 183
    .line 184
    invoke-interface {v12, v13}, Landroid/database/Cursor;->getLong(I)J

    .line 185
    .line 186
    .line 187
    move-result-wide v14

    .line 188
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    goto :goto_0

    .line 193
    :cond_3
    const-wide/16 v14, 0x0

    .line 194
    .line 195
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 196
    .line 197
    .line 198
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 199
    :goto_0
    invoke-interface {v12}, Landroid/database/Cursor;->close()V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 203
    .line 204
    .line 205
    move-result-wide v14

    .line 206
    new-instance v12, Landroid/app/job/JobInfo$Builder;

    .line 207
    .line 208
    invoke-direct {v12, v7, v4}, Landroid/app/job/JobInfo$Builder;-><init>(ILandroid/content/ComponentName;)V

    .line 209
    .line 210
    .line 211
    move-object v4, v6

    .line 212
    move/from16 v16, v7

    .line 213
    .line 214
    invoke-virtual {v3, v8, v14, v15, v2}, Lxn/a;->a(Lon/d;JI)J

    .line 215
    .line 216
    .line 217
    move-result-wide v6

    .line 218
    invoke-virtual {v12, v6, v7}, Landroid/app/job/JobInfo$Builder;->setMinimumLatency(J)Landroid/app/job/JobInfo$Builder;

    .line 219
    .line 220
    .line 221
    iget-object v6, v3, Lxn/a;->b:Ljava/util/HashMap;

    .line 222
    .line 223
    invoke-virtual {v6, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v6

    .line 227
    check-cast v6, Lxn/b;

    .line 228
    .line 229
    iget-object v6, v6, Lxn/b;->c:Ljava/util/Set;

    .line 230
    .line 231
    sget-object v7, Lxn/c;->d:Lxn/c;

    .line 232
    .line 233
    invoke-interface {v6, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v7

    .line 237
    const/4 v13, 0x1

    .line 238
    if-eqz v7, :cond_4

    .line 239
    .line 240
    const/4 v7, 0x2

    .line 241
    invoke-virtual {v12, v7}, Landroid/app/job/JobInfo$Builder;->setRequiredNetworkType(I)Landroid/app/job/JobInfo$Builder;

    .line 242
    .line 243
    .line 244
    goto :goto_1

    .line 245
    :cond_4
    invoke-virtual {v12, v13}, Landroid/app/job/JobInfo$Builder;->setRequiredNetworkType(I)Landroid/app/job/JobInfo$Builder;

    .line 246
    .line 247
    .line 248
    :goto_1
    sget-object v7, Lxn/c;->f:Lxn/c;

    .line 249
    .line 250
    invoke-interface {v6, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-result v7

    .line 254
    if-eqz v7, :cond_5

    .line 255
    .line 256
    invoke-virtual {v12, v13}, Landroid/app/job/JobInfo$Builder;->setRequiresCharging(Z)Landroid/app/job/JobInfo$Builder;

    .line 257
    .line 258
    .line 259
    :cond_5
    sget-object v7, Lxn/c;->e:Lxn/c;

    .line 260
    .line 261
    invoke-interface {v6, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v6

    .line 265
    if-eqz v6, :cond_6

    .line 266
    .line 267
    invoke-virtual {v12, v13}, Landroid/app/job/JobInfo$Builder;->setRequiresDeviceIdle(Z)Landroid/app/job/JobInfo$Builder;

    .line 268
    .line 269
    .line 270
    :cond_6
    new-instance v6, Landroid/os/PersistableBundle;

    .line 271
    .line 272
    invoke-direct {v6}, Landroid/os/PersistableBundle;-><init>()V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v6, v11, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 276
    .line 277
    .line 278
    const-string v7, "backendName"

    .line 279
    .line 280
    invoke-virtual {v6, v7, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    const-string v7, "priority"

    .line 284
    .line 285
    invoke-static {v8}, Lbo/a;->a(Lon/d;)I

    .line 286
    .line 287
    .line 288
    move-result v9

    .line 289
    invoke-virtual {v6, v7, v9}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 290
    .line 291
    .line 292
    if-eqz v5, :cond_7

    .line 293
    .line 294
    const-string v7, "extras"

    .line 295
    .line 296
    const/4 v9, 0x0

    .line 297
    invoke-static {v5, v9}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v5

    .line 301
    invoke-virtual {v6, v7, v5}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    :cond_7
    invoke-virtual {v12, v6}, Landroid/app/job/JobInfo$Builder;->setExtras(Landroid/os/PersistableBundle;)Landroid/app/job/JobInfo$Builder;

    .line 305
    .line 306
    .line 307
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 308
    .line 309
    .line 310
    move-result-object v5

    .line 311
    invoke-virtual {v3, v8, v14, v15, v2}, Lxn/a;->a(Lon/d;JI)J

    .line 312
    .line 313
    .line 314
    move-result-wide v6

    .line 315
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 316
    .line 317
    .line 318
    move-result-object v3

    .line 319
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    filled-new-array {v1, v5, v3, v0, v2}, [Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    const-string v1, "TRuntime."

    .line 328
    .line 329
    invoke-virtual {v1, v10}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    const/4 v2, 0x3

    .line 334
    invoke-static {v1, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 335
    .line 336
    .line 337
    move-result v2

    .line 338
    if-eqz v2, :cond_8

    .line 339
    .line 340
    const-string v2, "Scheduling upload for context %s with jobId=%d in %dms(Backend next call timestamp %d). Attempt %d"

    .line 341
    .line 342
    invoke-static {v2, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 347
    .line 348
    .line 349
    :cond_8
    invoke-virtual {v12}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    invoke-virtual {v4, v0}, Landroid/app/job/JobScheduler;->schedule(Landroid/app/job/JobInfo;)I

    .line 354
    .line 355
    .line 356
    return-void

    .line 357
    :catchall_0
    move-exception v0

    .line 358
    invoke-interface {v12}, Landroid/database/Cursor;->close()V

    .line 359
    .line 360
    .line 361
    throw v0
.end method
