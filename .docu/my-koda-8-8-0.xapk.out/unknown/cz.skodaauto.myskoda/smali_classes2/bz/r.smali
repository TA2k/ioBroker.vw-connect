.class public final Lbz/r;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzy/f;

.field public final i:Lzy/j;

.field public final j:Ltr0/b;

.field public final k:Lzy/z;

.field public final l:Lzy/v;

.field public final m:Lzy/q;

.field public final n:Lzy/o;

.field public final o:Lij0/a;


# direct methods
.method public constructor <init>(Lzy/f;Lzy/j;Ltr0/b;Lzy/z;Lzy/v;Lzy/q;Lzy/o;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Lbz/q;

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    const/4 v4, 0x0

    .line 5
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    move-object v3, v1

    .line 8
    move-object v5, v1

    .line 9
    move-object v6, v1

    .line 10
    invoke-direct/range {v0 .. v6}, Lbz/q;-><init>(Ljava/util/List;ILjava/util/List;ILjava/util/List;Ljava/util/List;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lbz/r;->h:Lzy/f;

    .line 17
    .line 18
    iput-object p2, p0, Lbz/r;->i:Lzy/j;

    .line 19
    .line 20
    iput-object p3, p0, Lbz/r;->j:Ltr0/b;

    .line 21
    .line 22
    iput-object p4, p0, Lbz/r;->k:Lzy/z;

    .line 23
    .line 24
    iput-object p5, p0, Lbz/r;->l:Lzy/v;

    .line 25
    .line 26
    iput-object p6, p0, Lbz/r;->m:Lzy/q;

    .line 27
    .line 28
    iput-object p7, p0, Lbz/r;->n:Lzy/o;

    .line 29
    .line 30
    iput-object p8, p0, Lbz/r;->o:Lij0/a;

    .line 31
    .line 32
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    new-instance p2, Lbz/o;

    .line 37
    .line 38
    const/4 p3, 0x0

    .line 39
    const/4 p4, 0x0

    .line 40
    invoke-direct {p2, p0, p4, p3}, Lbz/o;-><init>(Lbz/r;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x3

    .line 44
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public static final h(Lbz/r;Lrx0/i;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lbz/r;->h:Lzy/f;

    .line 2
    .line 3
    new-instance v1, Lzy/d;

    .line 4
    .line 5
    sget-object v2, Laz/h;->k:Lsx0/b;

    .line 6
    .line 7
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    check-cast v3, Lbz/q;

    .line 12
    .line 13
    iget v3, v3, Lbz/q;->d:I

    .line 14
    .line 15
    invoke-virtual {v2, v3}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Laz/h;

    .line 20
    .line 21
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    check-cast v3, Lbz/q;

    .line 26
    .line 27
    iget v3, v3, Lbz/q;->b:I

    .line 28
    .line 29
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, Lbz/q;

    .line 34
    .line 35
    iget-object v4, v4, Lbz/q;->f:Ljava/util/List;

    .line 36
    .line 37
    sget-object v5, Laz/f;->d:[Laz/f;

    .line 38
    .line 39
    new-instance v5, Ljava/lang/Integer;

    .line 40
    .line 41
    const/4 v6, 0x0

    .line 42
    invoke-direct {v5, v6}, Ljava/lang/Integer;-><init>(I)V

    .line 43
    .line 44
    .line 45
    invoke-interface {v4, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lbz/q;

    .line 54
    .line 55
    iget-object p0, p0, Lbz/q;->f:Ljava/util/List;

    .line 56
    .line 57
    new-instance v5, Ljava/lang/Integer;

    .line 58
    .line 59
    const/4 v6, 0x1

    .line 60
    invoke-direct {v5, v6}, Ljava/lang/Integer;-><init>(I)V

    .line 61
    .line 62
    .line 63
    invoke-interface {p0, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    invoke-direct {v1, v2, v3, v4, p0}, Lzy/d;-><init>(Laz/h;IZZ)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, v1, p1}, Lzy/f;->b(Lzy/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    if-ne p0, p1, :cond_0

    .line 77
    .line 78
    return-object p0

    .line 79
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object p0
.end method
