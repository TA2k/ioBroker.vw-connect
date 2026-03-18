.class public final Lh40/a1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbd0/c;

.field public final j:Lf40/p2;

.field public final k:Lf40/g;

.field public final l:Lij0/a;

.field public final m:Lf40/q0;

.field public final n:Lf40/p0;


# direct methods
.method public constructor <init>(Lf40/i0;Lf40/z;Ltr0/b;Lbd0/c;Lf40/p2;Lf40/g;Lij0/a;Lf40/q0;Lf40/p0;)V
    .locals 3

    .line 1
    new-instance v0, Lh40/z0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move-object v2, p5

    .line 5
    const/4 p5, 0x0

    .line 6
    invoke-direct {v0, p5, v1, p5}, Lh40/z0;-><init>(Lh40/y;ZLql0/g;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p3, p0, Lh40/a1;->h:Ltr0/b;

    .line 13
    .line 14
    iput-object p4, p0, Lh40/a1;->i:Lbd0/c;

    .line 15
    .line 16
    iput-object v2, p0, Lh40/a1;->j:Lf40/p2;

    .line 17
    .line 18
    iput-object p6, p0, Lh40/a1;->k:Lf40/g;

    .line 19
    .line 20
    iput-object p7, p0, Lh40/a1;->l:Lij0/a;

    .line 21
    .line 22
    iput-object p8, p0, Lh40/a1;->m:Lf40/q0;

    .line 23
    .line 24
    iput-object p9, p0, Lh40/a1;->n:Lf40/p0;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p6

    .line 30
    move-object p4, p0

    .line 31
    new-instance p0, Lg1/y2;

    .line 32
    .line 33
    move-object p3, p1

    .line 34
    const/4 p1, 0x7

    .line 35
    invoke-direct/range {p0 .. p5}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    const/4 p1, 0x3

    .line 39
    invoke-static {p6, p5, p5, p0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 40
    .line 41
    .line 42
    return-void
.end method
