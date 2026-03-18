.class public final Ld01/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/i;


# static fields
.field public static final F:Ljava/util/List;

.field public static final G:Ljava/util/List;


# instance fields
.field public final A:I

.field public final B:J

.field public final C:Lbu/c;

.field public final D:Lg01/c;

.field public final E:Lbu/c;

.field public final a:Ld01/t;

.field public final b:Ljava/util/List;

.field public final c:Ljava/util/List;

.field public final d:Lc1/y;

.field public final e:Z

.field public final f:Z

.field public final g:Ld01/c;

.field public final h:Z

.field public final i:Z

.field public final j:Ld01/r;

.field public final k:Ld01/g;

.field public final l:Ld01/r;

.field public final m:Ljava/net/ProxySelector;

.field public final n:Ld01/b;

.field public final o:Ljavax/net/SocketFactory;

.field public final p:Ljavax/net/ssl/SSLSocketFactory;

.field public final q:Ljavax/net/ssl/X509TrustManager;

.field public final r:Ljava/util/List;

.field public final s:Ljava/util/List;

.field public final t:Lr01/c;

.field public final u:Ld01/l;

.field public final v:Lkp/g;

.field public final w:I

.field public final x:I

.field public final y:I

.field public final z:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Ld01/i0;->i:Ld01/i0;

    .line 2
    .line 3
    sget-object v1, Ld01/i0;->g:Ld01/i0;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Ld01/i0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Le01/g;->k([Ljava/lang/Object;)Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Ld01/h0;->F:Ljava/util/List;

    .line 14
    .line 15
    sget-object v0, Ld01/p;->g:Ld01/p;

    .line 16
    .line 17
    sget-object v1, Ld01/p;->h:Ld01/p;

    .line 18
    .line 19
    filled-new-array {v0, v1}, [Ld01/p;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {v0}, Le01/g;->k([Ljava/lang/Object;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Ld01/h0;->G:Ljava/util/List;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 123
    new-instance v0, Ld01/g0;

    invoke-direct {v0}, Ld01/g0;-><init>()V

    invoke-direct {p0, v0}, Ld01/h0;-><init>(Ld01/g0;)V

    return-void
.end method

.method public constructor <init>(Ld01/g0;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iget-object v0, p1, Ld01/g0;->a:Ld01/t;

    .line 3
    iput-object v0, p0, Ld01/h0;->a:Ld01/t;

    .line 4
    iget-object v0, p1, Ld01/g0;->c:Ljava/util/ArrayList;

    .line 5
    invoke-static {v0}, Le01/g;->j(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Ld01/h0;->b:Ljava/util/List;

    .line 6
    iget-object v0, p1, Ld01/g0;->d:Ljava/util/ArrayList;

    .line 7
    invoke-static {v0}, Le01/g;->j(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Ld01/h0;->c:Ljava/util/List;

    .line 8
    iget-object v0, p1, Ld01/g0;->e:Lc1/y;

    .line 9
    iput-object v0, p0, Ld01/h0;->d:Lc1/y;

    .line 10
    iget-boolean v0, p1, Ld01/g0;->f:Z

    .line 11
    iput-boolean v0, p0, Ld01/h0;->e:Z

    .line 12
    iget-boolean v0, p1, Ld01/g0;->g:Z

    .line 13
    iput-boolean v0, p0, Ld01/h0;->f:Z

    .line 14
    iget-object v0, p1, Ld01/g0;->h:Ld01/c;

    .line 15
    iput-object v0, p0, Ld01/h0;->g:Ld01/c;

    .line 16
    iget-boolean v0, p1, Ld01/g0;->i:Z

    .line 17
    iput-boolean v0, p0, Ld01/h0;->h:Z

    .line 18
    iget-boolean v0, p1, Ld01/g0;->j:Z

    .line 19
    iput-boolean v0, p0, Ld01/h0;->i:Z

    .line 20
    iget-object v0, p1, Ld01/g0;->k:Ld01/r;

    .line 21
    iput-object v0, p0, Ld01/h0;->j:Ld01/r;

    .line 22
    iget-object v0, p1, Ld01/g0;->l:Ld01/g;

    .line 23
    iput-object v0, p0, Ld01/h0;->k:Ld01/g;

    .line 24
    iget-object v0, p1, Ld01/g0;->m:Ld01/r;

    .line 25
    iput-object v0, p0, Ld01/h0;->l:Ld01/r;

    .line 26
    iget-object v0, p1, Ld01/g0;->n:Ljava/net/ProxySelector;

    if-nez v0, :cond_0

    .line 27
    invoke-static {}, Ljava/net/ProxySelector;->getDefault()Ljava/net/ProxySelector;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v0, Lp01/a;->a:Lp01/a;

    .line 28
    :cond_0
    iput-object v0, p0, Ld01/h0;->m:Ljava/net/ProxySelector;

    .line 29
    iget-object v0, p1, Ld01/g0;->o:Ld01/b;

    .line 30
    iput-object v0, p0, Ld01/h0;->n:Ld01/b;

    .line 31
    iget-object v0, p1, Ld01/g0;->p:Ljavax/net/SocketFactory;

    .line 32
    iput-object v0, p0, Ld01/h0;->o:Ljavax/net/SocketFactory;

    .line 33
    iget-object v0, p1, Ld01/g0;->s:Ljava/util/List;

    .line 34
    iput-object v0, p0, Ld01/h0;->r:Ljava/util/List;

    .line 35
    iget-object v1, p1, Ld01/g0;->t:Ljava/util/List;

    .line 36
    iput-object v1, p0, Ld01/h0;->s:Ljava/util/List;

    .line 37
    iget-object v1, p1, Ld01/g0;->u:Lr01/c;

    .line 38
    iput-object v1, p0, Ld01/h0;->t:Lr01/c;

    .line 39
    iget v1, p1, Ld01/g0;->x:I

    .line 40
    iput v1, p0, Ld01/h0;->w:I

    .line 41
    iget v1, p1, Ld01/g0;->y:I

    .line 42
    iput v1, p0, Ld01/h0;->x:I

    .line 43
    iget v1, p1, Ld01/g0;->z:I

    .line 44
    iput v1, p0, Ld01/h0;->y:I

    .line 45
    iget v1, p1, Ld01/g0;->A:I

    .line 46
    iput v1, p0, Ld01/h0;->z:I

    .line 47
    iget v1, p1, Ld01/g0;->B:I

    .line 48
    iput v1, p0, Ld01/h0;->A:I

    .line 49
    iget-wide v1, p1, Ld01/g0;->C:J

    .line 50
    iput-wide v1, p0, Ld01/h0;->B:J

    .line 51
    iget-object v1, p1, Ld01/g0;->D:Lbu/c;

    if-nez v1, :cond_1

    .line 52
    new-instance v1, Lbu/c;

    const/16 v2, 0x1c

    invoke-direct {v1, v2}, Lbu/c;-><init>(I)V

    :cond_1
    iput-object v1, p0, Ld01/h0;->C:Lbu/c;

    .line 53
    iget-object v1, p1, Ld01/g0;->E:Lg01/c;

    if-nez v1, :cond_2

    .line 54
    sget-object v1, Lg01/c;->l:Lg01/c;

    :cond_2
    iput-object v1, p0, Ld01/h0;->D:Lg01/c;

    .line 55
    iget-object v1, p1, Ld01/g0;->b:Lbu/c;

    if-nez v1, :cond_3

    .line 56
    new-instance v1, Lbu/c;

    const/16 v2, 0xe

    invoke-direct {v1, v2}, Lbu/c;-><init>(I)V

    .line 57
    iput-object v1, p1, Ld01/g0;->b:Lbu/c;

    .line 58
    :cond_3
    iput-object v1, p0, Ld01/h0;->E:Lbu/c;

    .line 59
    check-cast v0, Ljava/lang/Iterable;

    .line 60
    instance-of v1, v0, Ljava/util/Collection;

    const/4 v2, 0x0

    if-eqz v1, :cond_4

    move-object v1, v0

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_4

    goto/16 :goto_2

    .line 61
    :cond_4
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_a

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ld01/p;

    .line 62
    iget-boolean v1, v1, Ld01/p;->a:Z

    if-eqz v1, :cond_5

    .line 63
    iget-object v0, p1, Ld01/g0;->q:Ljavax/net/ssl/SSLSocketFactory;

    if-eqz v0, :cond_7

    .line 64
    iput-object v0, p0, Ld01/h0;->p:Ljavax/net/ssl/SSLSocketFactory;

    .line 65
    iget-object v0, p1, Ld01/g0;->w:Lkp/g;

    .line 66
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    iput-object v0, p0, Ld01/h0;->v:Lkp/g;

    .line 67
    iget-object v1, p1, Ld01/g0;->r:Ljavax/net/ssl/X509TrustManager;

    .line 68
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    iput-object v1, p0, Ld01/h0;->q:Ljavax/net/ssl/X509TrustManager;

    .line 69
    iget-object p1, p1, Ld01/g0;->v:Ld01/l;

    .line 70
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    iget-object v1, p1, Ld01/l;->b:Lkp/g;

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_6

    goto :goto_0

    .line 72
    :cond_6
    new-instance v1, Ld01/l;

    iget-object p1, p1, Ld01/l;->a:Ljava/util/Set;

    invoke-direct {v1, p1, v0}, Ld01/l;-><init>(Ljava/util/Set;Lkp/g;)V

    move-object p1, v1

    .line 73
    :goto_0
    iput-object p1, p0, Ld01/h0;->u:Ld01/l;

    goto/16 :goto_3

    .line 74
    :cond_7
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 75
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 76
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    invoke-static {}, Ljavax/net/ssl/TrustManagerFactory;->getDefaultAlgorithm()Ljava/lang/String;

    move-result-object v0

    .line 78
    invoke-static {v0}, Ljavax/net/ssl/TrustManagerFactory;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;

    move-result-object v0

    .line 79
    invoke-virtual {v0, v2}, Ljavax/net/ssl/TrustManagerFactory;->init(Ljava/security/KeyStore;)V

    .line 80
    invoke-virtual {v0}, Ljavax/net/ssl/TrustManagerFactory;->getTrustManagers()[Ljavax/net/ssl/TrustManager;

    move-result-object v0

    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 81
    array-length v1, v0

    const/4 v3, 0x1

    if-ne v1, v3, :cond_9

    const/4 v1, 0x0

    aget-object v4, v0, v1

    instance-of v5, v4, Ljavax/net/ssl/X509TrustManager;

    if-eqz v5, :cond_9

    .line 82
    check-cast v4, Ljavax/net/ssl/X509TrustManager;

    .line 83
    iput-object v4, p0, Ld01/h0;->q:Ljavax/net/ssl/X509TrustManager;

    .line 84
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 85
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    :try_start_0
    invoke-virtual {v0}, Ln01/b;->e()Ljavax/net/ssl/SSLContext;

    move-result-object v0

    .line 87
    new-array v3, v3, [Ljavax/net/ssl/TrustManager;

    aput-object v4, v3, v1

    invoke-virtual {v0, v2, v3, v2}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V

    .line 88
    invoke-virtual {v0}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;

    move-result-object v0

    const-string v1, "getSocketFactory(...)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 89
    iput-object v0, p0, Ld01/h0;->p:Ljavax/net/ssl/SSLSocketFactory;

    .line 90
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 91
    invoke-virtual {v0, v4}, Ln01/b;->f(Ljavax/net/ssl/X509TrustManager;)Lkp/g;

    move-result-object v0

    .line 92
    iput-object v0, p0, Ld01/h0;->v:Lkp/g;

    .line 93
    iget-object p1, p1, Ld01/g0;->v:Ld01/l;

    .line 94
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    iget-object v1, p1, Ld01/l;->b:Lkp/g;

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_8

    goto :goto_1

    .line 96
    :cond_8
    new-instance v1, Ld01/l;

    iget-object p1, p1, Ld01/l;->a:Ljava/util/Set;

    invoke-direct {v1, p1, v0}, Ld01/l;-><init>(Ljava/util/Set;Lkp/g;)V

    move-object p1, v1

    .line 97
    :goto_1
    iput-object p1, p0, Ld01/h0;->u:Ld01/l;

    goto :goto_3

    :catch_0
    move-exception p0

    .line 98
    new-instance p1, Ljava/lang/AssertionError;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "No System TLS: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1

    .line 99
    :cond_9
    invoke-static {v0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "toString(...)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "Unexpected default trust managers: "

    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 100
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 101
    :cond_a
    :goto_2
    iput-object v2, p0, Ld01/h0;->p:Ljavax/net/ssl/SSLSocketFactory;

    .line 102
    iput-object v2, p0, Ld01/h0;->v:Lkp/g;

    .line 103
    iput-object v2, p0, Ld01/h0;->q:Ljavax/net/ssl/X509TrustManager;

    .line 104
    sget-object p1, Ld01/l;->c:Ld01/l;

    iput-object p1, p0, Ld01/h0;->u:Ld01/l;

    .line 105
    :goto_3
    iget-object p1, p0, Ld01/h0;->q:Ljavax/net/ssl/X509TrustManager;

    iget-object v0, p0, Ld01/h0;->v:Lkp/g;

    iget-object v1, p0, Ld01/h0;->p:Ljavax/net/ssl/SSLSocketFactory;

    iget-object v3, p0, Ld01/h0;->c:Ljava/util/List;

    iget-object v4, p0, Ld01/h0;->b:Ljava/util/List;

    const-string v5, "null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>"

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v4, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_16

    .line 106
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v3, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_15

    .line 107
    iget-object v2, p0, Ld01/h0;->r:Ljava/util/List;

    check-cast v2, Ljava/lang/Iterable;

    .line 108
    instance-of v3, v2, Ljava/util/Collection;

    if-eqz v3, :cond_b

    move-object v3, v2

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_b

    goto :goto_4

    .line 109
    :cond_b
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_c
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_10

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ld01/p;

    .line 110
    iget-boolean v3, v3, Ld01/p;->a:Z

    if-eqz v3, :cond_c

    if-eqz v1, :cond_f

    if-eqz v0, :cond_e

    if-eqz p1, :cond_d

    goto :goto_5

    .line 111
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "x509TrustManager == null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 112
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "certificateChainCleaner == null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 113
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "sslSocketFactory == null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 114
    :cond_10
    :goto_4
    const-string v2, "Check failed."

    if-nez v1, :cond_14

    if-nez v0, :cond_13

    if-nez p1, :cond_12

    .line 115
    iget-object p0, p0, Ld01/h0;->u:Ld01/l;

    sget-object p1, Ld01/l;->c:Ld01/l;

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_11

    :goto_5
    return-void

    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 116
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 117
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 118
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 119
    :cond_15
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "Null network interceptor: "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 120
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 121
    :cond_16
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "Null interceptor: "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    .line 122
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final a()Ld01/g0;
    .locals 3

    .line 1
    new-instance v0, Ld01/g0;

    .line 2
    .line 3
    invoke-direct {v0}, Ld01/g0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ld01/h0;->a:Ld01/t;

    .line 7
    .line 8
    iput-object v1, v0, Ld01/g0;->a:Ld01/t;

    .line 9
    .line 10
    iget-object v1, p0, Ld01/h0;->E:Lbu/c;

    .line 11
    .line 12
    iput-object v1, v0, Ld01/g0;->b:Lbu/c;

    .line 13
    .line 14
    iget-object v1, p0, Ld01/h0;->b:Ljava/util/List;

    .line 15
    .line 16
    check-cast v1, Ljava/lang/Iterable;

    .line 17
    .line 18
    iget-object v2, v0, Ld01/g0;->c:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-static {v1, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ld01/h0;->c:Ljava/util/List;

    .line 24
    .line 25
    check-cast v1, Ljava/lang/Iterable;

    .line 26
    .line 27
    iget-object v2, v0, Ld01/g0;->d:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-static {v1, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Ld01/h0;->d:Lc1/y;

    .line 33
    .line 34
    iput-object v1, v0, Ld01/g0;->e:Lc1/y;

    .line 35
    .line 36
    iget-boolean v1, p0, Ld01/h0;->e:Z

    .line 37
    .line 38
    iput-boolean v1, v0, Ld01/g0;->f:Z

    .line 39
    .line 40
    iget-boolean v1, p0, Ld01/h0;->f:Z

    .line 41
    .line 42
    iput-boolean v1, v0, Ld01/g0;->g:Z

    .line 43
    .line 44
    iget-object v1, p0, Ld01/h0;->g:Ld01/c;

    .line 45
    .line 46
    iput-object v1, v0, Ld01/g0;->h:Ld01/c;

    .line 47
    .line 48
    iget-boolean v1, p0, Ld01/h0;->h:Z

    .line 49
    .line 50
    iput-boolean v1, v0, Ld01/g0;->i:Z

    .line 51
    .line 52
    iget-boolean v1, p0, Ld01/h0;->i:Z

    .line 53
    .line 54
    iput-boolean v1, v0, Ld01/g0;->j:Z

    .line 55
    .line 56
    iget-object v1, p0, Ld01/h0;->j:Ld01/r;

    .line 57
    .line 58
    iput-object v1, v0, Ld01/g0;->k:Ld01/r;

    .line 59
    .line 60
    iget-object v1, p0, Ld01/h0;->k:Ld01/g;

    .line 61
    .line 62
    iput-object v1, v0, Ld01/g0;->l:Ld01/g;

    .line 63
    .line 64
    iget-object v1, p0, Ld01/h0;->l:Ld01/r;

    .line 65
    .line 66
    iput-object v1, v0, Ld01/g0;->m:Ld01/r;

    .line 67
    .line 68
    iget-object v1, p0, Ld01/h0;->m:Ljava/net/ProxySelector;

    .line 69
    .line 70
    iput-object v1, v0, Ld01/g0;->n:Ljava/net/ProxySelector;

    .line 71
    .line 72
    iget-object v1, p0, Ld01/h0;->n:Ld01/b;

    .line 73
    .line 74
    iput-object v1, v0, Ld01/g0;->o:Ld01/b;

    .line 75
    .line 76
    iget-object v1, p0, Ld01/h0;->o:Ljavax/net/SocketFactory;

    .line 77
    .line 78
    iput-object v1, v0, Ld01/g0;->p:Ljavax/net/SocketFactory;

    .line 79
    .line 80
    iget-object v1, p0, Ld01/h0;->p:Ljavax/net/ssl/SSLSocketFactory;

    .line 81
    .line 82
    iput-object v1, v0, Ld01/g0;->q:Ljavax/net/ssl/SSLSocketFactory;

    .line 83
    .line 84
    iget-object v1, p0, Ld01/h0;->q:Ljavax/net/ssl/X509TrustManager;

    .line 85
    .line 86
    iput-object v1, v0, Ld01/g0;->r:Ljavax/net/ssl/X509TrustManager;

    .line 87
    .line 88
    iget-object v1, p0, Ld01/h0;->r:Ljava/util/List;

    .line 89
    .line 90
    iput-object v1, v0, Ld01/g0;->s:Ljava/util/List;

    .line 91
    .line 92
    iget-object v1, p0, Ld01/h0;->s:Ljava/util/List;

    .line 93
    .line 94
    iput-object v1, v0, Ld01/g0;->t:Ljava/util/List;

    .line 95
    .line 96
    iget-object v1, p0, Ld01/h0;->t:Lr01/c;

    .line 97
    .line 98
    iput-object v1, v0, Ld01/g0;->u:Lr01/c;

    .line 99
    .line 100
    iget-object v1, p0, Ld01/h0;->u:Ld01/l;

    .line 101
    .line 102
    iput-object v1, v0, Ld01/g0;->v:Ld01/l;

    .line 103
    .line 104
    iget-object v1, p0, Ld01/h0;->v:Lkp/g;

    .line 105
    .line 106
    iput-object v1, v0, Ld01/g0;->w:Lkp/g;

    .line 107
    .line 108
    iget v1, p0, Ld01/h0;->w:I

    .line 109
    .line 110
    iput v1, v0, Ld01/g0;->x:I

    .line 111
    .line 112
    iget v1, p0, Ld01/h0;->x:I

    .line 113
    .line 114
    iput v1, v0, Ld01/g0;->y:I

    .line 115
    .line 116
    iget v1, p0, Ld01/h0;->y:I

    .line 117
    .line 118
    iput v1, v0, Ld01/g0;->z:I

    .line 119
    .line 120
    iget v1, p0, Ld01/h0;->z:I

    .line 121
    .line 122
    iput v1, v0, Ld01/g0;->A:I

    .line 123
    .line 124
    iget v1, p0, Ld01/h0;->A:I

    .line 125
    .line 126
    iput v1, v0, Ld01/g0;->B:I

    .line 127
    .line 128
    iget-wide v1, p0, Ld01/h0;->B:J

    .line 129
    .line 130
    iput-wide v1, v0, Ld01/g0;->C:J

    .line 131
    .line 132
    iget-object v1, p0, Ld01/h0;->C:Lbu/c;

    .line 133
    .line 134
    iput-object v1, v0, Ld01/g0;->D:Lbu/c;

    .line 135
    .line 136
    iget-object p0, p0, Ld01/h0;->D:Lg01/c;

    .line 137
    .line 138
    iput-object p0, v0, Ld01/g0;->E:Lg01/c;

    .line 139
    .line 140
    return-object v0
.end method

.method public final newCall(Ld01/k0;)Ld01/j;
    .locals 2

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh01/o;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, p1, v1}, Lh01/o;-><init>(Ld01/h0;Ld01/k0;Z)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method
