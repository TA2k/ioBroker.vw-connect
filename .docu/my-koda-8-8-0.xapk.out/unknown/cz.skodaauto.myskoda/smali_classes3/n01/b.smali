.class public final Ln01/b;
.super Ln01/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public c:Landroid/content/Context;

.field public final d:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>()V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lo01/a;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lo01/m;

    .line 10
    .line 11
    sget-object v2, Lo01/e;->e:Lmb/e;

    .line 12
    .line 13
    invoke-direct {v1, v2}, Lo01/m;-><init>(Lo01/l;)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Lo01/m;

    .line 17
    .line 18
    sget-object v3, Lo01/k;->a:Lo01/i;

    .line 19
    .line 20
    invoke-direct {v2, v3}, Lo01/m;-><init>(Lo01/l;)V

    .line 21
    .line 22
    .line 23
    new-instance v3, Lo01/m;

    .line 24
    .line 25
    sget-object v4, Lo01/h;->a:Lo01/f;

    .line 26
    .line 27
    invoke-direct {v3, v4}, Lo01/m;-><init>(Lo01/l;)V

    .line 28
    .line 29
    .line 30
    const/4 v4, 0x4

    .line 31
    new-array v4, v4, [Lo01/n;

    .line 32
    .line 33
    const/4 v5, 0x0

    .line 34
    aput-object v0, v4, v5

    .line 35
    .line 36
    const/4 v0, 0x1

    .line 37
    aput-object v1, v4, v0

    .line 38
    .line 39
    const/4 v0, 0x2

    .line 40
    aput-object v2, v4, v0

    .line 41
    .line 42
    const/4 v0, 0x3

    .line 43
    aput-object v3, v4, v0

    .line 44
    .line 45
    invoke-static {v4}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    new-instance v1, Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 52
    .line 53
    .line 54
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_1

    .line 63
    .line 64
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    move-object v3, v2

    .line 69
    check-cast v3, Lo01/n;

    .line 70
    .line 71
    invoke-interface {v3}, Lo01/n;->b()Z

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    if-eqz v3, :cond_0

    .line 76
    .line 77
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_1
    iput-object v1, p0, Ln01/b;->d:Ljava/util/ArrayList;

    .line 82
    .line 83
    return-void
.end method


# virtual methods
.method public final a(Ljavax/net/ssl/X509TrustManager;)Lr01/b;
    .locals 1

    .line 1
    const-string v0, "buildTrustRootIndex"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/StrictMode;->noteSlowCall(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ln01/d;->a(Ljavax/net/ssl/X509TrustManager;)Lr01/b;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final b()Ljava/lang/Object;
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1e

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    invoke-static {}, Ln01/a;->g()Landroid/util/CloseGuard;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Ld6/t1;->k(Landroid/util/CloseGuard;)V

    .line 12
    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-super {p0}, Ln01/d;->b()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final c(ILjava/lang/String;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    const-string p0, "message"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x5

    .line 7
    const-string v0, "OkHttp"

    .line 8
    .line 9
    if-ne p1, p0, :cond_0

    .line 10
    .line 11
    invoke-static {v0, p2, p3}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    invoke-static {v0, p2, p3}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final d(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    const/16 v1, 0x1e

    .line 9
    .line 10
    if-lt v0, v1, :cond_0

    .line 11
    .line 12
    const-string p0, "null cannot be cast to non-null type android.util.CloseGuard"

    .line 13
    .line 14
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Ld6/t1;->d(Ljava/lang/Object;)Landroid/util/CloseGuard;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-static {p0}, Ln01/a;->k(Landroid/util/CloseGuard;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    invoke-super {p0, p1, p2}, Ln01/d;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final e()Ljavax/net/ssl/SSLContext;
    .locals 1

    .line 1
    const-string v0, "newSSLContext"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/StrictMode;->noteSlowCall(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ln01/d;->e()Ljavax/net/ssl/SSLContext;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final f(Ljavax/net/ssl/X509TrustManager;)Lkp/g;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    new-instance v1, Landroid/net/http/X509TrustManagerExtensions;

    .line 3
    .line 4
    invoke-direct {v1, p1}, Landroid/net/http/X509TrustManagerExtensions;-><init>(Ljavax/net/ssl/X509TrustManager;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    .line 6
    .line 7
    goto :goto_0

    .line 8
    :catch_0
    move-object v1, v0

    .line 9
    :goto_0
    if-eqz v1, :cond_0

    .line 10
    .line 11
    new-instance v0, Lo01/b;

    .line 12
    .line 13
    invoke-direct {v0, p1, v1}, Lo01/b;-><init>(Ljavax/net/ssl/X509TrustManager;Landroid/net/http/X509TrustManagerExtensions;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    if-eqz v0, :cond_1

    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_1
    new-instance v0, Lr01/a;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ln01/b;->a(Ljavax/net/ssl/X509TrustManager;)Lr01/b;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-direct {v0, p0}, Lr01/a;-><init>(Lr01/b;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method
