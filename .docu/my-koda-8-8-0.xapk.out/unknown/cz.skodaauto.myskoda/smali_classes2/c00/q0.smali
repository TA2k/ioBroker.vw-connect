.class public final Lc00/q0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lb00/j;

.field public final j:Llb0/p;

.field public final k:Llb0/s;

.field public final l:Llb0/b0;

.field public final m:Lrq0/f;

.field public final n:Lyt0/b;

.field public final o:Ljn0/c;

.field public final p:Lij0/a;

.field public final q:Llb0/i;

.field public final r:Lqf0/g;


# direct methods
.method public constructor <init>(Ltr0/b;Lb00/j;Llb0/p;Llb0/s;Llb0/b0;Lrq0/f;Lyt0/b;Ljn0/c;Lij0/a;Llb0/i;Lqf0/g;)V
    .locals 11

    .line 1
    new-instance v0, Lc00/n0;

    .line 2
    .line 3
    const/4 v8, 0x0

    .line 4
    const v9, 0x7f1200c8

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    const/4 v10, 0x0

    .line 15
    invoke-direct/range {v0 .. v10}, Lc00/n0;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lc00/q0;->h:Ltr0/b;

    .line 22
    .line 23
    iput-object p2, p0, Lc00/q0;->i:Lb00/j;

    .line 24
    .line 25
    iput-object p3, p0, Lc00/q0;->j:Llb0/p;

    .line 26
    .line 27
    iput-object p4, p0, Lc00/q0;->k:Llb0/s;

    .line 28
    .line 29
    move-object/from16 p1, p5

    .line 30
    .line 31
    iput-object p1, p0, Lc00/q0;->l:Llb0/b0;

    .line 32
    .line 33
    move-object/from16 p1, p6

    .line 34
    .line 35
    iput-object p1, p0, Lc00/q0;->m:Lrq0/f;

    .line 36
    .line 37
    move-object/from16 p1, p7

    .line 38
    .line 39
    iput-object p1, p0, Lc00/q0;->n:Lyt0/b;

    .line 40
    .line 41
    move-object/from16 p1, p8

    .line 42
    .line 43
    iput-object p1, p0, Lc00/q0;->o:Ljn0/c;

    .line 44
    .line 45
    move-object/from16 p1, p9

    .line 46
    .line 47
    iput-object p1, p0, Lc00/q0;->p:Lij0/a;

    .line 48
    .line 49
    move-object/from16 p1, p10

    .line 50
    .line 51
    iput-object p1, p0, Lc00/q0;->q:Llb0/i;

    .line 52
    .line 53
    move-object/from16 p1, p11

    .line 54
    .line 55
    iput-object p1, p0, Lc00/q0;->r:Lqf0/g;

    .line 56
    .line 57
    new-instance p1, Lc00/m0;

    .line 58
    .line 59
    const/4 p2, 0x0

    .line 60
    const/4 p3, 0x0

    .line 61
    invoke-direct {p1, p0, p3, p2}, Lc00/m0;-><init>(Lc00/q0;Lkotlin/coroutines/Continuation;I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 65
    .line 66
    .line 67
    new-instance p1, Lc00/m0;

    .line 68
    .line 69
    const/4 p2, 0x1

    .line 70
    invoke-direct {p1, p0, p3, p2}, Lc00/m0;-><init>(Lc00/q0;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public static h(Ljava/lang/Boolean;)Z
    .locals 1

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method


# virtual methods
.method public final j(Lcn0/a;)Lc00/n0;
    .locals 12

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x5

    .line 6
    if-eq p1, v0, :cond_3

    .line 7
    .line 8
    const/4 v0, 0x6

    .line 9
    if-eq p1, v0, :cond_2

    .line 10
    .line 11
    const/4 v0, 0x7

    .line 12
    if-eq p1, v0, :cond_1

    .line 13
    .line 14
    const/16 v0, 0x8

    .line 15
    .line 16
    if-eq p1, v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lc00/n0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    move-object v0, p0

    .line 30
    check-cast v0, Lc00/n0;

    .line 31
    .line 32
    const/4 v10, 0x0

    .line 33
    const/16 v11, 0x3bf

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    const/4 v2, 0x0

    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v6, 0x0

    .line 41
    const/4 v7, 0x0

    .line 42
    const/4 v8, 0x0

    .line 43
    const/4 v9, 0x0

    .line 44
    invoke-static/range {v0 .. v11}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :cond_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    move-object v0, p0

    .line 54
    check-cast v0, Lc00/n0;

    .line 55
    .line 56
    const/4 v10, 0x0

    .line 57
    const/16 v11, 0x3f7

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
    const/4 v6, 0x0

    .line 65
    const/4 v7, 0x0

    .line 66
    const/4 v8, 0x0

    .line 67
    const/4 v9, 0x0

    .line 68
    invoke-static/range {v0 .. v11}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :cond_2
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    move-object v0, p0

    .line 78
    check-cast v0, Lc00/n0;

    .line 79
    .line 80
    const/4 v10, 0x0

    .line 81
    const/16 v11, 0x3df

    .line 82
    .line 83
    const/4 v1, 0x0

    .line 84
    const/4 v2, 0x0

    .line 85
    const/4 v3, 0x0

    .line 86
    const/4 v4, 0x0

    .line 87
    const/4 v5, 0x0

    .line 88
    const/4 v6, 0x0

    .line 89
    const/4 v7, 0x0

    .line 90
    const/4 v8, 0x0

    .line 91
    const/4 v9, 0x0

    .line 92
    invoke-static/range {v0 .. v11}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :cond_3
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    move-object v0, p0

    .line 102
    check-cast v0, Lc00/n0;

    .line 103
    .line 104
    const/4 v10, 0x0

    .line 105
    const/16 v11, 0x3ef

    .line 106
    .line 107
    const/4 v1, 0x0

    .line 108
    const/4 v2, 0x0

    .line 109
    const/4 v3, 0x0

    .line 110
    const/4 v4, 0x0

    .line 111
    const/4 v5, 0x0

    .line 112
    const/4 v6, 0x0

    .line 113
    const/4 v7, 0x0

    .line 114
    const/4 v8, 0x0

    .line 115
    const/4 v9, 0x0

    .line 116
    invoke-static/range {v0 .. v11}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0
.end method
