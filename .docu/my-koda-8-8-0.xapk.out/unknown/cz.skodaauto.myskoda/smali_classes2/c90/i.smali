.class public final Lc90/i;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lnr0/b;

.field public final j:La90/d0;

.field public final k:La90/k;

.field public final l:La90/n;

.field public final m:Lfj0/i;

.field public final n:Lnr0/a;


# direct methods
.method public constructor <init>(La90/x;La90/z;La90/j;Ltr0/b;Lnr0/b;La90/d0;La90/k;La90/n;Lfj0/i;Lnr0/a;)V
    .locals 9

    .line 1
    new-instance v0, Lc90/h;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    const/4 v4, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v5, 0x0

    .line 8
    const/4 v6, 0x0

    .line 9
    const/4 v7, 0x0

    .line 10
    invoke-direct/range {v0 .. v7}, Lc90/h;-><init>(ZZZZLjava/time/LocalDate;Ljava/time/LocalTime;Lb90/e;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p4, p0, Lc90/i;->h:Ltr0/b;

    .line 17
    .line 18
    iput-object p5, p0, Lc90/i;->i:Lnr0/b;

    .line 19
    .line 20
    iput-object p6, p0, Lc90/i;->j:La90/d0;

    .line 21
    .line 22
    move-object/from16 p4, p7

    .line 23
    .line 24
    iput-object p4, p0, Lc90/i;->k:La90/k;

    .line 25
    .line 26
    move-object/from16 p4, p8

    .line 27
    .line 28
    iput-object p4, p0, Lc90/i;->l:La90/n;

    .line 29
    .line 30
    move-object/from16 p4, p9

    .line 31
    .line 32
    iput-object p4, p0, Lc90/i;->m:Lfj0/i;

    .line 33
    .line 34
    move-object/from16 p4, p10

    .line 35
    .line 36
    iput-object p4, p0, Lc90/i;->n:Lnr0/a;

    .line 37
    .line 38
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object p4

    .line 42
    move-object v0, p4

    .line 43
    check-cast v0, Lc90/h;

    .line 44
    .line 45
    sget-object p4, Lb90/d;->f:Lb90/d;

    .line 46
    .line 47
    invoke-virtual {p3, p4}, La90/j;->a(Lb90/d;)Lb90/e;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    const/16 v8, 0x3f

    .line 52
    .line 53
    invoke-static/range {v0 .. v8}, Lc90/h;->a(Lc90/h;ZZZZLjava/time/LocalDate;Ljava/time/LocalTime;Lb90/e;I)Lc90/h;

    .line 54
    .line 55
    .line 56
    move-result-object p3

    .line 57
    invoke-virtual {p0, p3}, Lql0/j;->g(Lql0/h;)V

    .line 58
    .line 59
    .line 60
    new-instance p3, Lc90/g;

    .line 61
    .line 62
    const/4 p4, 0x0

    .line 63
    invoke-direct {p3, p0, p1, p2, p4}, Lc90/g;-><init>(Lc90/i;La90/x;La90/z;Lkotlin/coroutines/Continuation;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, p3}, Lql0/j;->b(Lay0/n;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method
