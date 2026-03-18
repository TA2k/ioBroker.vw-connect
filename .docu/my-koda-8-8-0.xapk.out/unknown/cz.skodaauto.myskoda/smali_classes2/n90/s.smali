.class public final Ln90/s;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/i;

.field public final i:Lkf0/l0;

.field public final j:Lkf0/q;

.field public final k:Ltr0/b;

.field public final l:Lqf0/g;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/p;Lkf0/i;Lkf0/l0;Lkf0/q;Ltr0/b;Lqf0/g;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Ln90/r;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    const/4 v4, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, ""

    .line 7
    .line 8
    const/4 v5, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Ln90/r;-><init>(Ljava/lang/String;Ljava/lang/String;ZZLql0/g;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Ln90/s;->h:Lkf0/i;

    .line 16
    .line 17
    iput-object p3, p0, Ln90/s;->i:Lkf0/l0;

    .line 18
    .line 19
    iput-object p4, p0, Ln90/s;->j:Lkf0/q;

    .line 20
    .line 21
    iput-object p5, p0, Ln90/s;->k:Ltr0/b;

    .line 22
    .line 23
    iput-object p6, p0, Ln90/s;->l:Lqf0/g;

    .line 24
    .line 25
    iput-object p7, p0, Ln90/s;->m:Lij0/a;

    .line 26
    .line 27
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    move-object v0, p2

    .line 32
    check-cast v0, Ln90/r;

    .line 33
    .line 34
    invoke-virtual {p1}, Lkf0/p;->invoke()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lss0/j0;

    .line 39
    .line 40
    const/4 p2, 0x0

    .line 41
    if-eqz p1, :cond_0

    .line 42
    .line 43
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 44
    .line 45
    move-object v1, p1

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move-object v1, p2

    .line 48
    :goto_0
    const/4 v5, 0x0

    .line 49
    const/16 v6, 0x1e

    .line 50
    .line 51
    const/4 v2, 0x0

    .line 52
    const/4 v3, 0x0

    .line 53
    const/4 v4, 0x0

    .line 54
    invoke-static/range {v0 .. v6}, Ln90/r;->a(Ln90/r;Ljava/lang/String;Ljava/lang/String;ZZLql0/g;I)Ln90/r;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 59
    .line 60
    .line 61
    new-instance p1, Lm70/i0;

    .line 62
    .line 63
    const/16 p3, 0x1c

    .line 64
    .line 65
    invoke-direct {p1, p0, p2, p3}, Lm70/i0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 69
    .line 70
    .line 71
    new-instance p1, Ln00/f;

    .line 72
    .line 73
    const/4 p3, 0x3

    .line 74
    invoke-direct {p1, p0, p2, p3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 78
    .line 79
    .line 80
    return-void
.end method
