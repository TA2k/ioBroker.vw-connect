.class public final Ldm0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final a:Lam0/u;

.field public final b:Lam0/z;

.field public final c:Ljava/util/concurrent/atomic/AtomicLong;


# direct methods
.method public constructor <init>(Lam0/u;Lam0/z;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldm0/o;->a:Lam0/u;

    .line 5
    .line 6
    iput-object p2, p0, Ldm0/o;->b:Lam0/z;

    .line 7
    .line 8
    new-instance p1, Ljava/util/concurrent/atomic/AtomicLong;

    .line 9
    .line 10
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    invoke-direct {p1, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ldm0/o;->c:Ljava/util/concurrent/atomic/AtomicLong;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 8

    .line 1
    move-object v3, p1

    .line 2
    check-cast v3, Li01/f;

    .line 3
    .line 4
    iget-object v4, v3, Li01/f;->e:Ld01/k0;

    .line 5
    .line 6
    :try_start_0
    check-cast p1, Li01/f;

    .line 7
    .line 8
    invoke-virtual {p1, v4}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 9
    .line 10
    .line 11
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    return-object p0

    .line 13
    :catch_0
    move-exception v0

    .line 14
    move-object p1, v0

    .line 15
    instance-of v0, p1, Ljavax/net/ssl/SSLHandshakeException;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    instance-of v0, p1, Ljava/security/cert/CertificateException;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    throw p1

    .line 25
    :cond_1
    :goto_0
    new-instance v0, Lac0/b;

    .line 26
    .line 27
    const/16 v1, 0xa

    .line 28
    .line 29
    invoke-direct {v0, v1, p1}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 30
    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-static {v5, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 34
    .line 35
    .line 36
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {v0}, Ljava/time/Instant;->toEpochMilli()J

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    const-wide/32 v6, 0x927c0

    .line 45
    .line 46
    .line 47
    sub-long v6, v0, v6

    .line 48
    .line 49
    new-instance v2, Ldm0/n;

    .line 50
    .line 51
    invoke-direct {v2, v0, v1}, Ldm0/n;-><init>(J)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Ldm0/o;->c:Ljava/util/concurrent/atomic/AtomicLong;

    .line 55
    .line 56
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicLong;->getAndUpdate(Ljava/util/function/LongUnaryOperator;)J

    .line 57
    .line 58
    .line 59
    move-result-wide v0

    .line 60
    cmp-long v0, v6, v0

    .line 61
    .line 62
    if-ltz v0, :cond_2

    .line 63
    .line 64
    new-instance v0, La7/o;

    .line 65
    .line 66
    const/16 v1, 0x1c

    .line 67
    .line 68
    move-object v2, p0

    .line 69
    invoke-direct/range {v0 .. v5}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 70
    .line 71
    .line 72
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 73
    .line 74
    invoke-static {p0, v0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    check-cast p0, Ld01/t0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_2
    throw p1
.end method
