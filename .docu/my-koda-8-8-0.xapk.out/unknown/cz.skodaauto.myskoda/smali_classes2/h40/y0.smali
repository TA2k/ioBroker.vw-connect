.class public final Lh40/y0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/b;

.field public final i:Lfo0/c;

.field public final j:Llm0/c;

.field public final k:Lf40/q0;

.field public final l:Lf40/p0;

.field public final m:Lf40/l4;

.field public final n:Lf40/o2;


# direct methods
.method public constructor <init>(Lf40/h0;Lfo0/b;Lfo0/c;Llm0/c;Lf40/q0;Lf40/p0;Lf40/l4;Lf40/o2;)V
    .locals 4

    .line 1
    new-instance v0, Lh40/x0;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v2, v1, v1, v3}, Lh40/x0;-><init>(ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lh40/y0;->h:Lfo0/b;

    .line 14
    .line 15
    iput-object p3, p0, Lh40/y0;->i:Lfo0/c;

    .line 16
    .line 17
    iput-object p4, p0, Lh40/y0;->j:Llm0/c;

    .line 18
    .line 19
    iput-object p5, p0, Lh40/y0;->k:Lf40/q0;

    .line 20
    .line 21
    iput-object p6, p0, Lh40/y0;->l:Lf40/p0;

    .line 22
    .line 23
    iput-object p7, p0, Lh40/y0;->m:Lf40/l4;

    .line 24
    .line 25
    iput-object p8, p0, Lh40/y0;->n:Lf40/o2;

    .line 26
    .line 27
    invoke-virtual {p1}, Lf40/h0;->invoke()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    check-cast p1, Lg40/f;

    .line 32
    .line 33
    if-eqz p1, :cond_1

    .line 34
    .line 35
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    move-object p3, p2

    .line 40
    check-cast p3, Lh40/x0;

    .line 41
    .line 42
    iget-object p5, p1, Lg40/f;->b:Ljava/lang/String;

    .line 43
    .line 44
    iget-object p6, p1, Lg40/f;->c:Ljava/lang/String;

    .line 45
    .line 46
    iget-object p1, p1, Lg40/f;->f:Ljava/util/List;

    .line 47
    .line 48
    invoke-static {p1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, Ljava/lang/String;

    .line 53
    .line 54
    if-eqz p1, :cond_0

    .line 55
    .line 56
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    move-object p7, p1

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move-object p7, v3

    .line 63
    :goto_0
    const/4 p8, 0x1

    .line 64
    const/4 p4, 0x0

    .line 65
    invoke-static/range {p3 .. p8}, Lh40/x0;->a(Lh40/x0;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;I)Lh40/x0;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 70
    .line 71
    .line 72
    :cond_1
    new-instance p1, La7/y0;

    .line 73
    .line 74
    const/4 p2, 0x1

    .line 75
    invoke-direct {p1, p0, v3, p2}, La7/y0;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method
