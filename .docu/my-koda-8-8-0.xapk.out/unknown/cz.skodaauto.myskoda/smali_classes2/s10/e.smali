.class public final Ls10/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lq10/s;

.field public final i:Lrq0/f;

.field public final j:Ljn0/c;

.field public final k:Lyt0/b;

.field public final l:Lij0/a;

.field public final m:Lq10/x;


# direct methods
.method public constructor <init>(Lq10/l;Lq10/i;Lkf0/v;Lq10/s;Lrq0/f;Ljn0/c;Lyt0/b;Lij0/a;Lq10/x;)V
    .locals 3

    .line 1
    new-instance v0, Ls10/b;

    .line 2
    .line 3
    const/16 v1, 0xff

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ls10/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p4, p0, Ls10/e;->h:Lq10/s;

    .line 12
    .line 13
    iput-object p5, p0, Ls10/e;->i:Lrq0/f;

    .line 14
    .line 15
    iput-object p6, p0, Ls10/e;->j:Ljn0/c;

    .line 16
    .line 17
    iput-object p7, p0, Ls10/e;->k:Lyt0/b;

    .line 18
    .line 19
    iput-object p8, p0, Ls10/e;->l:Lij0/a;

    .line 20
    .line 21
    iput-object p9, p0, Ls10/e;->m:Lq10/x;

    .line 22
    .line 23
    move-object p4, p2

    .line 24
    move-object p2, p0

    .line 25
    new-instance p0, Lh7/z;

    .line 26
    .line 27
    const/4 p5, 0x0

    .line 28
    const/16 p6, 0x19

    .line 29
    .line 30
    move-object v2, p3

    .line 31
    move-object p3, p1

    .line 32
    move-object p1, v2

    .line 33
    invoke-direct/range {p0 .. p6}, Lh7/z;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p2, p0}, Lql0/j;->b(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public static final h(Ls10/e;)V
    .locals 10

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Ls10/b;

    .line 7
    .line 8
    new-instance v0, Lqr0/q;

    .line 9
    .line 10
    const-wide/high16 v2, 0x4036000000000000L    # 22.0

    .line 11
    .line 12
    sget-object v4, Lqr0/r;->d:Lqr0/r;

    .line 13
    .line 14
    invoke-direct {v0, v2, v3, v4}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, p0, Ls10/e;->l:Lij0/a;

    .line 18
    .line 19
    invoke-static {v0, v2}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    new-instance v0, Lqr0/l;

    .line 24
    .line 25
    const/16 v2, 0x14

    .line 26
    .line 27
    invoke-direct {v0, v2}, Lqr0/l;-><init>(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {v0}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    const/4 v8, 0x0

    .line 35
    const/16 v9, 0x40

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    const/16 v4, 0x14

    .line 39
    .line 40
    const/16 v6, 0x14

    .line 41
    .line 42
    const/4 v7, 0x0

    .line 43
    invoke-static/range {v1 .. v9}, Ls10/b;->a(Ls10/b;Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZI)Ls10/b;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public static final j(Ls10/e;Lcn0/c;Ls10/d;)Ljava/lang/Object;
    .locals 11

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v1, p0, Ls10/e;->i:Lrq0/f;

    .line 4
    .line 5
    iget-object v2, p0, Ls10/e;->j:Ljn0/c;

    .line 6
    .line 7
    iget-object v3, p0, Ls10/e;->k:Lyt0/b;

    .line 8
    .line 9
    iget-object v4, p0, Ls10/e;->l:Lij0/a;

    .line 10
    .line 11
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 12
    .line 13
    .line 14
    move-result-object v5

    .line 15
    new-instance v6, Lo51/c;

    .line 16
    .line 17
    const/16 v0, 0x12

    .line 18
    .line 19
    invoke-direct {v6, v0, p0, p1}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 v8, 0x0

    .line 23
    const/16 v10, 0x1c0

    .line 24
    .line 25
    const/4 v7, 0x0

    .line 26
    move-object v0, p1

    .line 27
    move-object v9, p2

    .line 28
    invoke-static/range {v0 .. v10}, Ljp/fg;->f(Lcn0/c;Lrq0/f;Ljn0/c;Lyt0/b;Lij0/a;Lvy0/b0;Lay0/a;Lay0/k;Lay0/a;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    if-ne p0, p1, :cond_0

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0
.end method
