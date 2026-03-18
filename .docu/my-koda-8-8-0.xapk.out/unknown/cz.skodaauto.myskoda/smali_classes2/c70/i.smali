.class public final Lc70/i;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lep0/g;

.field public final i:Lep0/a;

.field public final j:Ltr0/b;

.field public final k:Lcs0/l;

.field public final l:Lrq0/d;

.field public final m:La70/a;

.field public final n:La70/c;

.field public final o:Lkf0/v;

.field public final p:Ltn0/b;

.field public final q:Lij0/a;

.field public final r:Lep0/e;


# direct methods
.method public constructor <init>(Lep0/g;Lep0/a;Ltr0/b;Lcs0/l;Lrq0/d;La70/a;La70/c;Lkf0/v;Ltn0/b;Lij0/a;Lep0/e;)V
    .locals 13

    .line 1
    new-instance v0, Lc70/h;

    .line 2
    .line 3
    sget-object v1, Ler0/g;->d:Ler0/g;

    .line 4
    .line 5
    sget-object v2, Llf0/i;->j:Llf0/i;

    .line 6
    .line 7
    new-instance v8, Lvf0/j;

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    const/16 v4, 0x7f

    .line 11
    .line 12
    const/4 v12, 0x0

    .line 13
    invoke-direct {v8, v12, v4, v12, v3}, Lvf0/j;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    .line 14
    .line 15
    .line 16
    sget-object v9, Lqr0/s;->d:Lqr0/s;

    .line 17
    .line 18
    const/4 v10, 0x0

    .line 19
    const/4 v4, 0x0

    .line 20
    const/4 v5, 0x0

    .line 21
    const/4 v6, 0x0

    .line 22
    const/4 v7, 0x0

    .line 23
    const/4 v11, 0x0

    .line 24
    invoke-direct/range {v0 .. v11}, Lc70/h;-><init>(Ler0/g;Llf0/i;ZZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lc70/i;->h:Lep0/g;

    .line 31
    .line 32
    iput-object p2, p0, Lc70/i;->i:Lep0/a;

    .line 33
    .line 34
    move-object/from16 p1, p3

    .line 35
    .line 36
    iput-object p1, p0, Lc70/i;->j:Ltr0/b;

    .line 37
    .line 38
    move-object/from16 p1, p4

    .line 39
    .line 40
    iput-object p1, p0, Lc70/i;->k:Lcs0/l;

    .line 41
    .line 42
    move-object/from16 p1, p5

    .line 43
    .line 44
    iput-object p1, p0, Lc70/i;->l:Lrq0/d;

    .line 45
    .line 46
    move-object/from16 p1, p6

    .line 47
    .line 48
    iput-object p1, p0, Lc70/i;->m:La70/a;

    .line 49
    .line 50
    move-object/from16 p1, p7

    .line 51
    .line 52
    iput-object p1, p0, Lc70/i;->n:La70/c;

    .line 53
    .line 54
    move-object/from16 p1, p8

    .line 55
    .line 56
    iput-object p1, p0, Lc70/i;->o:Lkf0/v;

    .line 57
    .line 58
    move-object/from16 p1, p9

    .line 59
    .line 60
    iput-object p1, p0, Lc70/i;->p:Ltn0/b;

    .line 61
    .line 62
    move-object/from16 p1, p10

    .line 63
    .line 64
    iput-object p1, p0, Lc70/i;->q:Lij0/a;

    .line 65
    .line 66
    move-object/from16 p1, p11

    .line 67
    .line 68
    iput-object p1, p0, Lc70/i;->r:Lep0/e;

    .line 69
    .line 70
    new-instance p1, Lc70/f;

    .line 71
    .line 72
    const/4 p2, 0x0

    .line 73
    invoke-direct {p1, p0, v12, p2}, Lc70/f;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 77
    .line 78
    .line 79
    new-instance p1, La50/c;

    .line 80
    .line 81
    const/16 p2, 0x1c

    .line 82
    .line 83
    invoke-direct {p1, p0, v12, p2}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 87
    .line 88
    .line 89
    return-void
.end method


# virtual methods
.method public final h(Lne0/c;)V
    .locals 12

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, La50/c;

    .line 6
    .line 7
    const/16 v2, 0x1d

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, v2, p0, p1, v3}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Lc70/h;

    .line 22
    .line 23
    iget-boolean p1, p1, Lc70/h;->c:Z

    .line 24
    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    check-cast p1, Lc70/h;

    .line 32
    .line 33
    iget-object v0, p0, Lc70/i;->q:Lij0/a;

    .line 34
    .line 35
    invoke-static {p1, v0}, Ljp/fd;->m(Lc70/h;Lij0/a;)Lc70/h;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    move-object v0, p1

    .line 47
    check-cast v0, Lc70/h;

    .line 48
    .line 49
    const/4 v10, 0x0

    .line 50
    const/16 v11, 0x7fb

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    const/4 v2, 0x0

    .line 54
    const/4 v3, 0x0

    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v6, 0x0

    .line 58
    const/4 v7, 0x0

    .line 59
    const/4 v8, 0x0

    .line 60
    const/4 v9, 0x0

    .line 61
    invoke-static/range {v0 .. v11}, Lc70/h;->a(Lc70/h;Ler0/g;Llf0/i;ZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;I)Lc70/h;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method
