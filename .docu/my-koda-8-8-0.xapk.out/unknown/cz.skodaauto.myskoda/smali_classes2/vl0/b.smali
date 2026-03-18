.class public final Lvl0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lez0/a;

.field public final i:Ltl0/b;


# direct methods
.method public constructor <init>(Ltl0/b;)V
    .locals 8

    .line 1
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lvl0/a;

    .line 6
    .line 7
    new-instance v2, Lul0/c;

    .line 8
    .line 9
    sget-object v3, Lul0/a;->d:Lul0/a;

    .line 10
    .line 11
    const/4 v6, 0x0

    .line 12
    const/16 v7, 0x3e

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, 0x0

    .line 16
    invoke-direct/range {v2 .. v7}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 17
    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-direct {v1, v2, v3}, Lvl0/a;-><init>(Lul0/e;Z)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lvl0/b;->h:Lez0/a;

    .line 27
    .line 28
    iput-object p1, p0, Lvl0/b;->i:Ltl0/b;

    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    new-instance v0, La7/w0;

    .line 35
    .line 36
    const/4 v1, 0x5

    .line 37
    const/4 v2, 0x0

    .line 38
    invoke-direct {v0, p0, v2, v1}, La7/w0;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    return-void
.end method
