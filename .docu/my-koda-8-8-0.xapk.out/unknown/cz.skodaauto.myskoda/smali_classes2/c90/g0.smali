.class public final Lc90/g0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:La90/t;

.field public final j:La90/g;

.field public final k:Lij0/a;

.field public final l:Lnr0/d;

.field public final m:La90/f0;

.field public final n:Lfj0/i;

.field public final o:Lnr0/a;


# direct methods
.method public constructor <init>(La90/j;Ltr0/b;La90/t;La90/g;Lij0/a;Lnr0/d;La90/f0;Lfj0/i;Lnr0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lc90/e0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v3, v2, v3}, Lc90/e0;-><init>(ZLql0/g;Ljava/util/List;Lb90/e;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lc90/g0;->h:Ltr0/b;

    .line 14
    .line 15
    iput-object p3, p0, Lc90/g0;->i:La90/t;

    .line 16
    .line 17
    iput-object p4, p0, Lc90/g0;->j:La90/g;

    .line 18
    .line 19
    iput-object p5, p0, Lc90/g0;->k:Lij0/a;

    .line 20
    .line 21
    iput-object p6, p0, Lc90/g0;->l:Lnr0/d;

    .line 22
    .line 23
    iput-object p7, p0, Lc90/g0;->m:La90/f0;

    .line 24
    .line 25
    iput-object p8, p0, Lc90/g0;->n:Lfj0/i;

    .line 26
    .line 27
    iput-object p9, p0, Lc90/g0;->o:Lnr0/a;

    .line 28
    .line 29
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    move-object p3, p2

    .line 34
    check-cast p3, Lc90/e0;

    .line 35
    .line 36
    sget-object p2, Lb90/d;->d:Lb90/d;

    .line 37
    .line 38
    invoke-virtual {p1, p2}, La90/j;->a(Lb90/d;)Lb90/e;

    .line 39
    .line 40
    .line 41
    move-result-object p7

    .line 42
    const/4 p8, 0x7

    .line 43
    const/4 p4, 0x0

    .line 44
    const/4 p5, 0x0

    .line 45
    const/4 p6, 0x0

    .line 46
    invoke-static/range {p3 .. p8}, Lc90/e0;->a(Lc90/e0;ZLql0/g;Ljava/util/ArrayList;Lb90/e;I)Lc90/e0;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 51
    .line 52
    .line 53
    new-instance p1, Lc90/d0;

    .line 54
    .line 55
    const/4 p2, 0x0

    .line 56
    invoke-direct {p1, p0, v3, p2}, Lc90/d0;-><init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 60
    .line 61
    .line 62
    return-void
.end method
