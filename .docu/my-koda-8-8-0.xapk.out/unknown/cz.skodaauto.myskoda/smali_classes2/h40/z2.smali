.class public final Lh40/z2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lij0/a;

.field public final j:Lf40/k1;

.field public final k:Lf40/a4;


# direct methods
.method public constructor <init>(Ltr0/b;Lij0/a;Lf40/k1;Lf40/a4;Lf40/e3;Lf40/u;Lf40/n1;)V
    .locals 5

    .line 1
    new-instance v0, Lh40/y2;

    .line 2
    .line 3
    sget-object v1, Lg40/u0;->d:Lg40/u0;

    .line 4
    .line 5
    move-object v2, p4

    .line 6
    move-object p4, p5

    .line 7
    const/4 p5, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v4, v3, v1, v3}, Lh40/y2;-><init>(ZLql0/g;Lg40/u0;Lg40/i0;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lh40/z2;->h:Ltr0/b;

    .line 17
    .line 18
    iput-object p2, p0, Lh40/z2;->i:Lij0/a;

    .line 19
    .line 20
    iput-object p3, p0, Lh40/z2;->j:Lf40/k1;

    .line 21
    .line 22
    iput-object v2, p0, Lh40/z2;->k:Lf40/a4;

    .line 23
    .line 24
    move-object p3, p0

    .line 25
    new-instance p0, Lg1/y2;

    .line 26
    .line 27
    const/16 p1, 0xb

    .line 28
    .line 29
    move-object p2, p6

    .line 30
    invoke-direct/range {p0 .. p5}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p3, p0}, Lql0/j;->b(Lay0/n;)V

    .line 34
    .line 35
    .line 36
    new-instance p0, Lg60/w;

    .line 37
    .line 38
    const/16 p1, 0x1b

    .line 39
    .line 40
    invoke-direct {p0, p1, p7, p3, p5}, Lg60/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p3, p0}, Lql0/j;->b(Lay0/n;)V

    .line 44
    .line 45
    .line 46
    invoke-static {p3}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    new-instance p1, Lh40/h;

    .line 51
    .line 52
    const/4 p2, 0x6

    .line 53
    invoke-direct {p1, p3, p5, p2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    const/4 p2, 0x3

    .line 57
    invoke-static {p0, p5, p5, p1, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 58
    .line 59
    .line 60
    return-void
.end method
