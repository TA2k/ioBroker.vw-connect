.class public final Lro0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/s;


# direct methods
.method public constructor <init>(Lro0/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lro0/j;->a:Lro0/s;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lro0/j;->a:Lro0/s;

    .line 2
    .line 3
    check-cast v0, Lpo0/d;

    .line 4
    .line 5
    iget-object v0, v0, Lpo0/d;->a:Lro0/u;

    .line 6
    .line 7
    new-instance v1, Lp81/c;

    .line 8
    .line 9
    const/16 v2, 0x10

    .line 10
    .line 11
    invoke-direct {v1, v2}, Lp81/c;-><init>(I)V

    .line 12
    .line 13
    .line 14
    check-cast v0, Lpo0/e;

    .line 15
    .line 16
    iget-object v0, v0, Lpo0/e;->a:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lyy0/i;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v1, Lne0/c;

    .line 28
    .line 29
    new-instance v2, Llx0/g;

    .line 30
    .line 31
    invoke-direct {v2}, Llx0/g;-><init>()V

    .line 32
    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    const/16 v6, 0x1e

    .line 36
    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x0

    .line 39
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 40
    .line 41
    .line 42
    new-instance v0, Lyy0/m;

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    invoke-direct {v0, v1, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    :goto_0
    new-instance v1, Lnz/g;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    const/16 v3, 0x19

    .line 52
    .line 53
    invoke-direct {v1, p0, v2, v3}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    new-instance p0, Lne0/n;

    .line 57
    .line 58
    const/4 v2, 0x5

    .line 59
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 60
    .line 61
    .line 62
    return-object p0
.end method
