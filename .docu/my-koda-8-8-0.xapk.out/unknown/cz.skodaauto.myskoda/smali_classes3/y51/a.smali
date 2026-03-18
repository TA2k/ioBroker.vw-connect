.class public final Ly51/a;
.super Landroid/net/ConnectivityManager$NetworkCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:[I

.field public final synthetic b:Landroid/net/ConnectivityManager;

.field public final synthetic c:Lxy0/x;

.field public final synthetic d:Ly51/e;


# direct methods
.method public constructor <init>([ILandroid/net/ConnectivityManager;Lxy0/x;Ly51/e;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ly51/a;->a:[I

    .line 2
    .line 3
    iput-object p2, p0, Ly51/a;->b:Landroid/net/ConnectivityManager;

    .line 4
    .line 5
    iput-object p3, p0, Ly51/a;->c:Lxy0/x;

    .line 6
    .line 7
    iput-object p4, p0, Ly51/a;->d:Ly51/e;

    .line 8
    .line 9
    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final onAvailable(Landroid/net/Network;)V
    .locals 8

    .line 1
    const-string v0, "network"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v4, p0, Ly51/a;->b:Landroid/net/ConnectivityManager;

    .line 7
    .line 8
    invoke-virtual {v4}, Landroid/net/ConnectivityManager;->getActiveNetwork()Landroid/net/Network;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v7, p0, Ly51/a;->c:Lxy0/x;

    .line 17
    .line 18
    iget-object v1, p0, Ly51/a;->a:[I

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    array-length v0, v1

    .line 23
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([II)[I

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const/4 v6, 0x4

    .line 28
    const-string v2, "onAvailable"

    .line 29
    .line 30
    iget-object v5, p0, Ly51/a;->d:Ly51/e;

    .line 31
    .line 32
    move-object v1, p1

    .line 33
    invoke-static/range {v1 .. v6}, Llp/zf;->c(Landroid/net/Network;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;I)V

    .line 34
    .line 35
    .line 36
    check-cast v7, Lxy0/w;

    .line 37
    .line 38
    invoke-virtual {v7, v5}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    move-object p0, v1

    .line 43
    move-object v1, p1

    .line 44
    array-length p1, p0

    .line 45
    invoke-static {p0, p1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {}, Llp/zf;->a()Ly51/e;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    const-string v2, "onAvailable"

    .line 54
    .line 55
    const-string v3, "VPN"

    .line 56
    .line 57
    move-object v5, v4

    .line 58
    move-object v4, p0

    .line 59
    invoke-static/range {v1 .. v6}, Llp/zf;->b(Landroid/net/Network;Ljava/lang/String;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;)V

    .line 60
    .line 61
    .line 62
    invoke-static {}, Llp/zf;->a()Ly51/e;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast v7, Lxy0/w;

    .line 67
    .line 68
    invoke-virtual {v7, p0}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final onLost(Landroid/net/Network;)V
    .locals 8

    .line 1
    const-string v0, "network"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ly51/a;->a:[I

    .line 7
    .line 8
    array-length v1, v0

    .line 9
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    const/4 v7, 0x4

    .line 14
    const-string v3, "onLost"

    .line 15
    .line 16
    iget-object v5, p0, Ly51/a;->b:Landroid/net/ConnectivityManager;

    .line 17
    .line 18
    sget-object v6, Ly51/d;->a:Ly51/d;

    .line 19
    .line 20
    move-object v2, p1

    .line 21
    invoke-static/range {v2 .. v7}, Llp/zf;->c(Landroid/net/Network;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;I)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Ly51/a;->c:Lxy0/x;

    .line 25
    .line 26
    check-cast p0, Lxy0/w;

    .line 27
    .line 28
    invoke-virtual {p0, v6}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    invoke-static {}, Llp/zf;->a()Ly51/e;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final onUnavailable()V
    .locals 8

    .line 1
    iget-object v0, p0, Ly51/a;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 5
    .line 6
    .line 7
    move-result-object v4

    .line 8
    const/4 v7, 0x5

    .line 9
    const/4 v2, 0x0

    .line 10
    const-string v3, "onAvailable"

    .line 11
    .line 12
    iget-object v5, p0, Ly51/a;->b:Landroid/net/ConnectivityManager;

    .line 13
    .line 14
    sget-object v6, Ly51/d;->a:Ly51/d;

    .line 15
    .line 16
    invoke-static/range {v2 .. v7}, Llp/zf;->c(Landroid/net/Network;Ljava/lang/String;[ILandroid/net/ConnectivityManager;Ly51/e;I)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Ly51/a;->c:Lxy0/x;

    .line 20
    .line 21
    check-cast p0, Lxy0/w;

    .line 22
    .line 23
    invoke-virtual {p0, v6}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-void
.end method
