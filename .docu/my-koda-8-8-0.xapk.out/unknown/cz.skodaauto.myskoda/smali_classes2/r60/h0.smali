.class public final Lr60/h0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/k;

.field public final i:Ltr0/b;

.field public final j:Lp60/g;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/k;Ltr0/b;Lp60/g;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Lr60/g0;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v2, v1

    .line 10
    invoke-direct/range {v0 .. v6}, Lr60/g0;-><init>(Ljava/util/List;Ljava/util/List;Lql0/g;ZZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lr60/h0;->h:Lkf0/k;

    .line 17
    .line 18
    iput-object p2, p0, Lr60/h0;->i:Ltr0/b;

    .line 19
    .line 20
    iput-object p3, p0, Lr60/h0;->j:Lp60/g;

    .line 21
    .line 22
    iput-object p4, p0, Lr60/h0;->k:Lij0/a;

    .line 23
    .line 24
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance p2, Lny/f0;

    .line 29
    .line 30
    const/16 p3, 0x13

    .line 31
    .line 32
    const/4 p4, 0x0

    .line 33
    invoke-direct {p2, p0, p4, p3}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    const/4 p0, 0x3

    .line 37
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    return-void
.end method
