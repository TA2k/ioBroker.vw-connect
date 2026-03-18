.class public final Lro0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/r;


# direct methods
.method public constructor <init>(Lro0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lro0/i;->a:Lro0/r;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lro0/i;->a:Lro0/r;

    .line 2
    .line 3
    check-cast v0, Lpo0/c;

    .line 4
    .line 5
    iget-object v0, v0, Lpo0/c;->a:Lro0/u;

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
    invoke-virtual {v0}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->getLegalRepository()Lcj/f;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ldj/g;

    .line 18
    .line 19
    iget-object v0, v0, Ldj/g;->c:Llx0/q;

    .line 20
    .line 21
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lyy0/a2;

    .line 26
    .line 27
    new-instance v1, Lp81/c;

    .line 28
    .line 29
    const/16 v2, 0xf

    .line 30
    .line 31
    invoke-direct {v1, v2}, Lp81/c;-><init>(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v0, v1}, Ljp/td;->a(Lyy0/a2;Lay0/k;)Lne0/k;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    new-instance v1, Lne0/c;

    .line 40
    .line 41
    new-instance v2, Llx0/g;

    .line 42
    .line 43
    invoke-direct {v2}, Llx0/g;-><init>()V

    .line 44
    .line 45
    .line 46
    const/4 v5, 0x0

    .line 47
    const/16 v6, 0x1e

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    const/4 v4, 0x0

    .line 51
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 52
    .line 53
    .line 54
    new-instance v0, Lyy0/m;

    .line 55
    .line 56
    const/4 v2, 0x0

    .line 57
    invoke-direct {v0, v1, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    :goto_0
    new-instance v1, Lnz/g;

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    const/16 v3, 0x18

    .line 64
    .line 65
    invoke-direct {v1, p0, v2, v3}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    new-instance p0, Lne0/n;

    .line 69
    .line 70
    const/4 v2, 0x5

    .line 71
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 72
    .line 73
    .line 74
    return-object p0
.end method
