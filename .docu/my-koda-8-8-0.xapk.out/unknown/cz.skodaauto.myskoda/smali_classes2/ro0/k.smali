.class public final Lro0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/v;


# direct methods
.method public constructor <init>(Lro0/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lro0/k;->a:Lro0/v;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lro0/k;->a:Lro0/v;

    .line 2
    .line 3
    check-cast v0, Lpo0/h;

    .line 4
    .line 5
    iget-object v0, v0, Lpo0/h;->a:Lro0/u;

    .line 6
    .line 7
    check-cast v0, Lpo0/e;

    .line 8
    .line 9
    iget-object v0, v0, Lpo0/e;->a:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->getSubscriptionRepository()Llj/f;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lmj/k;

    .line 18
    .line 19
    iget-object v0, v0, Lmj/k;->j:Lyy0/c2;

    .line 20
    .line 21
    new-instance v1, Lp81/c;

    .line 22
    .line 23
    const/16 v2, 0x12

    .line 24
    .line 25
    invoke-direct {v1, v2}, Lp81/c;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v1}, Ljp/td;->a(Lyy0/a2;Lay0/k;)Lne0/k;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance v1, Lne0/c;

    .line 34
    .line 35
    new-instance v2, Llx0/g;

    .line 36
    .line 37
    invoke-direct {v2}, Llx0/g;-><init>()V

    .line 38
    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    const/16 v6, 0x1e

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    const/4 v4, 0x0

    .line 45
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 46
    .line 47
    .line 48
    new-instance v0, Lyy0/m;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    invoke-direct {v0, v1, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    :goto_0
    new-instance v1, Lnz/g;

    .line 55
    .line 56
    const/4 v2, 0x0

    .line 57
    const/16 v3, 0x1a

    .line 58
    .line 59
    invoke-direct {v1, p0, v2, v3}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 60
    .line 61
    .line 62
    new-instance p0, Lne0/n;

    .line 63
    .line 64
    const/4 v2, 0x5

    .line 65
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 66
    .line 67
    .line 68
    return-object p0
.end method
