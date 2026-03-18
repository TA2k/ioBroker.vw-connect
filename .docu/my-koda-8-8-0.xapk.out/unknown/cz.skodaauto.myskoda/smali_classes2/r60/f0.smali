.class public final Lr60/f0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lnn0/a;

.field public final i:Lnn0/e;

.field public final j:Lnn0/h;

.field public final k:Lkf0/k;

.field public final l:Lp60/n;

.field public final m:Lp60/p;

.field public final n:Lp60/q;

.field public final o:Lnn0/a0;

.field public final p:Lp60/t;

.field public final q:Lp60/y;

.field public final r:Lbd0/c;

.field public final s:Lnn0/x;

.field public final t:Lij0/a;

.field public final u:Ltr0/b;

.field public final v:Lhh0/a;

.field public final w:Lp60/w;


# direct methods
.method public constructor <init>(Lnn0/a;Lnn0/e;Lnn0/h;Lkf0/k;Lp60/n;Lp60/p;Lp60/q;Lnn0/a0;Lp60/t;Lp60/y;Lbd0/c;Lnn0/x;Lij0/a;Ltr0/b;Lhh0/a;Lp60/w;)V
    .locals 7

    .line 1
    new-instance v0, Lr60/e0;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    sget-object v5, Ler0/g;->d:Ler0/g;

    .line 5
    .line 6
    const-string v1, ""

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x1

    .line 10
    move-object v6, v1

    .line 11
    invoke-direct/range {v0 .. v6}, Lr60/e0;-><init>(Ljava/lang/String;Lql0/g;ZZLer0/g;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lr60/f0;->h:Lnn0/a;

    .line 18
    .line 19
    iput-object p2, p0, Lr60/f0;->i:Lnn0/e;

    .line 20
    .line 21
    iput-object p3, p0, Lr60/f0;->j:Lnn0/h;

    .line 22
    .line 23
    iput-object p4, p0, Lr60/f0;->k:Lkf0/k;

    .line 24
    .line 25
    iput-object p5, p0, Lr60/f0;->l:Lp60/n;

    .line 26
    .line 27
    iput-object p6, p0, Lr60/f0;->m:Lp60/p;

    .line 28
    .line 29
    iput-object p7, p0, Lr60/f0;->n:Lp60/q;

    .line 30
    .line 31
    iput-object p8, p0, Lr60/f0;->o:Lnn0/a0;

    .line 32
    .line 33
    move-object/from16 p1, p9

    .line 34
    .line 35
    iput-object p1, p0, Lr60/f0;->p:Lp60/t;

    .line 36
    .line 37
    move-object/from16 p1, p10

    .line 38
    .line 39
    iput-object p1, p0, Lr60/f0;->q:Lp60/y;

    .line 40
    .line 41
    move-object/from16 p1, p11

    .line 42
    .line 43
    iput-object p1, p0, Lr60/f0;->r:Lbd0/c;

    .line 44
    .line 45
    move-object/from16 p1, p12

    .line 46
    .line 47
    iput-object p1, p0, Lr60/f0;->s:Lnn0/x;

    .line 48
    .line 49
    move-object/from16 p1, p13

    .line 50
    .line 51
    iput-object p1, p0, Lr60/f0;->t:Lij0/a;

    .line 52
    .line 53
    move-object/from16 p1, p14

    .line 54
    .line 55
    iput-object p1, p0, Lr60/f0;->u:Ltr0/b;

    .line 56
    .line 57
    move-object/from16 p1, p15

    .line 58
    .line 59
    iput-object p1, p0, Lr60/f0;->v:Lhh0/a;

    .line 60
    .line 61
    move-object/from16 p1, p16

    .line 62
    .line 63
    iput-object p1, p0, Lr60/f0;->w:Lp60/w;

    .line 64
    .line 65
    new-instance p1, Lk90/b;

    .line 66
    .line 67
    const/4 p2, 0x0

    .line 68
    invoke-direct {p1, p0, p2}, Lk90/b;-><init>(Lr60/f0;Lkotlin/coroutines/Continuation;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public static final h(Lr60/f0;Lon0/c;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lr60/f0;->p:Lp60/t;

    .line 2
    .line 3
    iget-object v1, p0, Lr60/f0;->o:Lnn0/a0;

    .line 4
    .line 5
    sget-object v2, Lon0/b;->d:Lon0/b;

    .line 6
    .line 7
    iget-object v1, v1, Lnn0/a0;->a:Lln0/b;

    .line 8
    .line 9
    iput-object v2, v1, Lln0/b;->a:Lon0/b;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p1, :cond_4

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    if-eq p1, v1, :cond_3

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    if-eq p1, v1, :cond_2

    .line 22
    .line 23
    const/4 v1, 0x3

    .line 24
    if-eq p1, v1, :cond_1

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    if-ne p1, v0, :cond_0

    .line 28
    .line 29
    iget-object p0, p0, Lr60/f0;->m:Lp60/p;

    .line 30
    .line 31
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, La8/r0;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_3
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    move-object v0, p1

    .line 54
    check-cast v0, Lr60/e0;

    .line 55
    .line 56
    const/4 v6, 0x0

    .line 57
    const/16 v7, 0x3b

    .line 58
    .line 59
    const/4 v1, 0x0

    .line 60
    const/4 v2, 0x0

    .line 61
    const/4 v3, 0x0

    .line 62
    const/4 v4, 0x0

    .line 63
    const/4 v5, 0x0

    .line 64
    invoke-static/range {v0 .. v7}, Lr60/e0;->a(Lr60/e0;Ljava/lang/String;Lql0/g;ZZLer0/g;Ljava/lang/String;I)Lr60/e0;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_4
    iget-object p0, p0, Lr60/f0;->n:Lp60/q;

    .line 73
    .line 74
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    return-void
.end method
