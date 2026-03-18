.class public final Lh40/d2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Ltr0/b;

.field public final j:Lbd0/c;

.field public final k:Lf40/l;

.field public final l:Lf40/i2;


# direct methods
.method public constructor <init>(Lf40/l0;Lij0/a;Ltr0/b;Lbd0/c;Lf40/l;Lf40/i2;)V
    .locals 9

    .line 1
    new-instance v0, Lh40/c2;

    .line 2
    .line 3
    const/16 v1, 0x7f

    .line 4
    .line 5
    and-int/lit8 v1, v1, 0x1

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    invoke-direct/range {v0 .. v7}, Lh40/c2;-><init>(Lh40/m3;ZZZIZLql0/g;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 18
    .line 19
    .line 20
    iput-object p2, p0, Lh40/d2;->h:Lij0/a;

    .line 21
    .line 22
    iput-object p3, p0, Lh40/d2;->i:Ltr0/b;

    .line 23
    .line 24
    iput-object p4, p0, Lh40/d2;->j:Lbd0/c;

    .line 25
    .line 26
    iput-object p5, p0, Lh40/d2;->k:Lf40/l;

    .line 27
    .line 28
    iput-object p6, p0, Lh40/d2;->l:Lf40/i2;

    .line 29
    .line 30
    invoke-virtual {p1}, Lf40/l0;->invoke()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p1, Lg40/d0;

    .line 35
    .line 36
    if-eqz p1, :cond_0

    .line 37
    .line 38
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object p3

    .line 42
    move-object v0, p3

    .line 43
    check-cast v0, Lh40/c2;

    .line 44
    .line 45
    invoke-static {p1, p2}, Lla/w;->a(Lg40/d0;Lij0/a;)Lh40/m3;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    const/4 v7, 0x0

    .line 50
    const/16 v8, 0x7e

    .line 51
    .line 52
    const/4 v2, 0x0

    .line 53
    const/4 v3, 0x0

    .line 54
    const/4 v4, 0x0

    .line 55
    const/4 v5, 0x0

    .line 56
    const/4 v6, 0x0

    .line 57
    invoke-static/range {v0 .. v8}, Lh40/c2;->a(Lh40/c2;Lh40/m3;ZZZIZLql0/g;I)Lh40/c2;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 62
    .line 63
    .line 64
    :cond_0
    return-void
.end method
