.class public final Lw30/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcs0/i;

.field public final i:Lcs0/j0;

.field public final j:Lwi0/d;


# direct methods
.method public constructor <init>(Lcs0/i;Lcs0/j0;Lwi0/d;)V
    .locals 3

    .line 1
    new-instance v0, Lw30/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    invoke-direct {v0, v1, v2}, Lw30/i;-><init>(ZLjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lw30/j;->h:Lcs0/i;

    .line 13
    .line 14
    iput-object p2, p0, Lw30/j;->i:Lcs0/j0;

    .line 15
    .line 16
    iput-object p3, p0, Lw30/j;->j:Lwi0/d;

    .line 17
    .line 18
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance p2, Lvu/j;

    .line 23
    .line 24
    const/16 p3, 0xa

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    invoke-direct {p2, p0, v0, p3}, Lvu/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    const/4 p0, 0x3

    .line 31
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 32
    .line 33
    .line 34
    return-void
.end method
