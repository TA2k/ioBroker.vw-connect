.class public final Lk20/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Li20/n;

.field public final i:Lrs0/e;

.field public final j:Ltr0/b;


# direct methods
.method public constructor <init>(Li20/e;Lij0/a;Li20/n;Lrs0/e;Ltr0/b;)V
    .locals 4

    .line 1
    new-instance v0, Lk20/d;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    move-object v3, p5

    .line 7
    const/4 p5, 0x0

    .line 8
    invoke-direct {v0, v1, p5, v2}, Lk20/d;-><init>(Ljava/lang/String;Lhp0/e;Z)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 12
    .line 13
    .line 14
    iput-object p3, p0, Lk20/e;->h:Li20/n;

    .line 15
    .line 16
    iput-object p4, p0, Lk20/e;->i:Lrs0/e;

    .line 17
    .line 18
    iput-object v3, p0, Lk20/e;->j:Ltr0/b;

    .line 19
    .line 20
    invoke-virtual {p1}, Li20/e;->invoke()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    move-object p4, p1

    .line 25
    check-cast p4, Lj20/c;

    .line 26
    .line 27
    if-eqz p4, :cond_0

    .line 28
    .line 29
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    move-object p3, p2

    .line 34
    move-object p2, p0

    .line 35
    new-instance p0, Lg1/y2;

    .line 36
    .line 37
    const/16 p1, 0x1d

    .line 38
    .line 39
    invoke-direct/range {p0 .. p5}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    const/4 p1, 0x3

    .line 43
    invoke-static {v0, p5, p5, p0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 44
    .line 45
    .line 46
    :cond_0
    return-void
.end method
