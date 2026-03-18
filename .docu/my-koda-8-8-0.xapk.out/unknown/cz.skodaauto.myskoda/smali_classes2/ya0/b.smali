.class public final Lya0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwa0/e;

.field public final i:Lcs0/l;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lwa0/e;Lcs0/l;Lij0/a;)V
    .locals 11

    .line 1
    new-instance v0, Lya0/a;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const/4 v4, 0x0

    .line 7
    const/4 v6, 0x0

    .line 8
    const/4 v9, 0x0

    .line 9
    move-object v2, v1

    .line 10
    move-object v3, v1

    .line 11
    move-object v7, v1

    .line 12
    move-object v8, v1

    .line 13
    move-object v10, v1

    .line 14
    invoke-direct/range {v0 .. v10}, Lya0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lya0/b;->h:Lwa0/e;

    .line 21
    .line 22
    iput-object p2, p0, Lya0/b;->i:Lcs0/l;

    .line 23
    .line 24
    iput-object p3, p0, Lya0/b;->j:Lij0/a;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lvo0/e;

    .line 31
    .line 32
    const/16 p3, 0x1d

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    invoke-direct {p2, p0, v0, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x3

    .line 39
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 40
    .line 41
    .line 42
    return-void
.end method
