.class public final Lh50/b1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lpp0/l0;

.field public final i:Lpp0/f1;

.field public final j:Ltr0/b;

.field public final k:Lal0/y;

.field public final l:Lal0/h1;

.field public m:Lqp0/r;


# direct methods
.method public constructor <init>(Lpp0/l0;Lpp0/f1;Ltr0/b;Lal0/y;Lal0/h1;)V
    .locals 8

    .line 1
    new-instance v0, Lh50/a1;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    const/4 v7, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    invoke-direct/range {v0 .. v7}, Lh50/a1;-><init>(ZZZZZZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lh50/b1;->h:Lpp0/l0;

    .line 17
    .line 18
    iput-object p2, p0, Lh50/b1;->i:Lpp0/f1;

    .line 19
    .line 20
    iput-object p3, p0, Lh50/b1;->j:Ltr0/b;

    .line 21
    .line 22
    iput-object p4, p0, Lh50/b1;->k:Lal0/y;

    .line 23
    .line 24
    iput-object p5, p0, Lh50/b1;->l:Lal0/h1;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lh50/z0;

    .line 31
    .line 32
    const/4 p3, 0x0

    .line 33
    const/4 p4, 0x0

    .line 34
    invoke-direct {p2, p0, p4, p3}, Lh50/z0;-><init>(Lh50/b1;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p3, 0x3

    .line 38
    invoke-static {p1, p4, p4, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    new-instance p1, Lh50/z0;

    .line 42
    .line 43
    const/4 p2, 0x1

    .line 44
    invoke-direct {p1, p0, p4, p2}, Lh50/z0;-><init>(Lh50/b1;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final h(Lqp0/r;)V
    .locals 10

    .line 1
    iput-object p1, p0, Lh50/b1;->m:Lqp0/r;

    .line 2
    .line 3
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lh50/a1;

    .line 9
    .line 10
    iget-boolean v2, p1, Lqp0/r;->a:Z

    .line 11
    .line 12
    iget-boolean v3, p1, Lqp0/r;->b:Z

    .line 13
    .line 14
    iget-boolean v4, p1, Lqp0/r;->c:Z

    .line 15
    .line 16
    iget-boolean v5, p1, Lqp0/r;->d:Z

    .line 17
    .line 18
    iget-boolean v6, p1, Lqp0/r;->g:Z

    .line 19
    .line 20
    const/4 v8, 0x0

    .line 21
    const/16 v9, 0x60

    .line 22
    .line 23
    const/4 v7, 0x0

    .line 24
    invoke-static/range {v1 .. v9}, Lh50/a1;->a(Lh50/a1;ZZZZZZZI)Lh50/a1;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
