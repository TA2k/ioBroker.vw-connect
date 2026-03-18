.class public final Ly70/p0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lw70/h0;

.field public final i:Lw70/u0;

.field public j:Lz21/a;


# direct methods
.method public constructor <init>(Lw70/t;Lw70/h0;Lw70/u0;)V
    .locals 6

    .line 1
    new-instance v0, Ly70/n0;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    const/4 v5, 0x1

    .line 5
    const-string v1, ""

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Ly70/n0;-><init>(Ljava/lang/String;ZZZZ)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Ly70/p0;->h:Lw70/h0;

    .line 16
    .line 17
    iput-object p3, p0, Ly70/p0;->i:Lw70/u0;

    .line 18
    .line 19
    sget-object p2, Lz21/a;->d:Lz21/a;

    .line 20
    .line 21
    iput-object p2, p0, Ly70/p0;->j:Lz21/a;

    .line 22
    .line 23
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    new-instance p3, Lwp0/c;

    .line 28
    .line 29
    const/16 v0, 0x11

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {p3, v0, p1, p0, v1}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    const/4 p0, 0x3

    .line 36
    invoke-static {p2, v1, v1, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 37
    .line 38
    .line 39
    return-void
.end method
