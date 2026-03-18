.class public final Lh40/q2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/x1;


# direct methods
.method public constructor <init>(Lf40/h0;Lf40/z;Ltr0/b;Lf40/x1;)V
    .locals 7

    .line 1
    new-instance v0, Lh40/p2;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    invoke-direct {v0, v6}, Lh40/p2;-><init>(Lh40/x;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p3, p0, Lh40/q2;->h:Ltr0/b;

    .line 11
    .line 12
    iput-object p4, p0, Lh40/q2;->i:Lf40/x1;

    .line 13
    .line 14
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 15
    .line 16
    .line 17
    move-result-object p3

    .line 18
    new-instance v1, Lg1/y2;

    .line 19
    .line 20
    const/16 v2, 0xa

    .line 21
    .line 22
    move-object v5, p0

    .line 23
    move-object v4, p1

    .line 24
    move-object v3, p2

    .line 25
    invoke-direct/range {v1 .. v6}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x3

    .line 29
    invoke-static {p3, v6, v6, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    return-void
.end method
