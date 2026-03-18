.class public abstract Lkb/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "NetworkStateTracker"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "tagWithPrefix(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lkb/g;->a:Ljava/lang/String;

    .line 13
    .line 14
    return-void
.end method

.method public static final a(Landroid/net/ConnectivityManager;)Lib/e;
    .locals 8

    .line 1
    sget-object v0, Lkb/g;->a:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    :try_start_0
    invoke-virtual {p0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    invoke-virtual {v3}, Landroid/net/NetworkInfo;->isConnected()Z

    .line 17
    .line 18
    .line 19
    move-result v4
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    if-eqz v4, :cond_0

    .line 21
    .line 22
    move v4, v1

    .line 23
    goto :goto_0

    .line 24
    :catch_0
    move-exception p0

    .line 25
    goto :goto_5

    .line 26
    :cond_0
    move v4, v2

    .line 27
    :goto_0
    :try_start_1
    invoke-virtual {p0}, Landroid/net/ConnectivityManager;->getActiveNetwork()Landroid/net/Network;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-virtual {p0, v5}, Landroid/net/ConnectivityManager;->getNetworkCapabilities(Landroid/net/Network;)Landroid/net/NetworkCapabilities;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    const/16 v6, 0x10

    .line 38
    .line 39
    invoke-virtual {v5, v6}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 40
    .line 41
    .line 42
    move-result v5
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_1

    .line 43
    goto :goto_3

    .line 44
    :catch_1
    move-exception v5

    .line 45
    goto :goto_2

    .line 46
    :cond_1
    :goto_1
    move v5, v2

    .line 47
    goto :goto_3

    .line 48
    :goto_2
    :try_start_2
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    const-string v7, "Unable to validate active network"

    .line 53
    .line 54
    invoke-virtual {v6, v0, v7, v5}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :goto_3
    invoke-virtual {p0}, Landroid/net/ConnectivityManager;->isActiveNetworkMetered()Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-eqz v3, :cond_2

    .line 63
    .line 64
    invoke-virtual {v3}, Landroid/net/NetworkInfo;->isRoaming()Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-nez v3, :cond_2

    .line 69
    .line 70
    move v3, v1

    .line 71
    goto :goto_4

    .line 72
    :cond_2
    move v3, v2

    .line 73
    :goto_4
    new-instance v6, Lib/e;

    .line 74
    .line 75
    invoke-direct {v6, v4, v5, p0, v3}, Lib/e;-><init>(ZZZZ)V
    :try_end_2
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_0

    .line 76
    .line 77
    .line 78
    return-object v6

    .line 79
    :goto_5
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    const-string v4, "Unable to get active network state"

    .line 84
    .line 85
    invoke-virtual {v3, v0, v4, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 86
    .line 87
    .line 88
    new-instance p0, Lib/e;

    .line 89
    .line 90
    invoke-direct {p0, v2, v2, v2, v1}, Lib/e;-><init>(ZZZZ)V

    .line 91
    .line 92
    .line 93
    return-object p0
.end method
