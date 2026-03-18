.class public final Lk30/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Li30/b;

.field public final i:Li30/h;

.field public final j:Li30/e;

.field public final k:Ltr0/b;

.field public final l:Li30/a;

.field public final m:Lij0/a;

.field public final n:Lkf0/v;

.field public final o:Lrq0/d;


# direct methods
.method public constructor <init>(Li30/b;Li30/h;Li30/e;Ltr0/b;Li30/a;Lij0/a;Lkf0/v;Lrq0/d;)V
    .locals 13

    .line 1
    new-instance v0, Lk30/e;

    .line 2
    .line 3
    sget-object v1, Lss0/e;->O1:Lss0/e;

    .line 4
    .line 5
    sget-object v11, Ler0/g;->d:Ler0/g;

    .line 6
    .line 7
    sget-object v12, Llf0/i;->j:Llf0/i;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    const-string v4, ""

    .line 12
    .line 13
    const/4 v6, 0x0

    .line 14
    sget-object v7, Lmx0/s;->d:Lmx0/s;

    .line 15
    .line 16
    const/4 v8, 0x0

    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x0

    .line 19
    move-object v5, v4

    .line 20
    invoke-direct/range {v0 .. v12}, Lk30/e;-><init>(Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/List;ZZLql0/g;Ler0/g;Llf0/i;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lk30/h;->h:Li30/b;

    .line 27
    .line 28
    iput-object p2, p0, Lk30/h;->i:Li30/h;

    .line 29
    .line 30
    move-object/from16 p1, p3

    .line 31
    .line 32
    iput-object p1, p0, Lk30/h;->j:Li30/e;

    .line 33
    .line 34
    move-object/from16 p1, p4

    .line 35
    .line 36
    iput-object p1, p0, Lk30/h;->k:Ltr0/b;

    .line 37
    .line 38
    move-object/from16 p1, p5

    .line 39
    .line 40
    iput-object p1, p0, Lk30/h;->l:Li30/a;

    .line 41
    .line 42
    move-object/from16 p1, p6

    .line 43
    .line 44
    iput-object p1, p0, Lk30/h;->m:Lij0/a;

    .line 45
    .line 46
    move-object/from16 p1, p7

    .line 47
    .line 48
    iput-object p1, p0, Lk30/h;->n:Lkf0/v;

    .line 49
    .line 50
    move-object/from16 p1, p8

    .line 51
    .line 52
    iput-object p1, p0, Lk30/h;->o:Lrq0/d;

    .line 53
    .line 54
    new-instance p1, Lif0/d0;

    .line 55
    .line 56
    const/4 p2, 0x0

    .line 57
    const/16 v0, 0x19

    .line 58
    .line 59
    invoke-direct {p1, p0, p2, v0}, Lif0/d0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method

.method public static final h(Lk30/h;Lss0/b;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    sget-object v2, Lj30/a;->m:Lsx0/b;

    .line 9
    .line 10
    new-instance v3, Ljava/util/ArrayList;

    .line 11
    .line 12
    const/16 v4, 0xa

    .line 13
    .line 14
    invoke-static {v2, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 15
    .line 16
    .line 17
    move-result v5

    .line 18
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    if-eqz v5, :cond_0

    .line 30
    .line 31
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    check-cast v5, Lj30/a;

    .line 36
    .line 37
    new-instance v6, Lj30/b;

    .line 38
    .line 39
    sget-object v7, Lmx0/s;->d:Lmx0/s;

    .line 40
    .line 41
    invoke-direct {v6, v5, v7}, Lj30/b;-><init>(Lj30/a;Ljava/util/List;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    move-object v5, v2

    .line 53
    check-cast v5, Lk30/e;

    .line 54
    .line 55
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    const-string v6, "now(...)"

    .line 60
    .line 61
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-static {v2}, Lvo/a;->j(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    invoke-static {v3}, Lk30/h;->k(Ljava/util/ArrayList;)Z

    .line 69
    .line 70
    .line 71
    move-result v11

    .line 72
    invoke-virtual {v0, v3}, Lk30/h;->j(Ljava/util/ArrayList;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v10

    .line 76
    new-instance v12, Ljava/util/ArrayList;

    .line 77
    .line 78
    invoke-static {v3, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    invoke-direct {v12, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    if-eqz v3, :cond_1

    .line 94
    .line 95
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Lj30/b;

    .line 100
    .line 101
    invoke-virtual {v0, v3}, Lk30/h;->q(Lj30/b;)Lk30/d;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-virtual {v12, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_1
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    check-cast v2, Lk30/e;

    .line 114
    .line 115
    iget-object v2, v2, Lk30/e;->a:Lss0/e;

    .line 116
    .line 117
    invoke-static {v1, v2}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 118
    .line 119
    .line 120
    move-result-object v17

    .line 121
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    check-cast v2, Lk30/e;

    .line 126
    .line 127
    iget-object v2, v2, Lk30/e;->a:Lss0/e;

    .line 128
    .line 129
    invoke-static {v1, v2}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 130
    .line 131
    .line 132
    move-result-object v16

    .line 133
    const/4 v15, 0x0

    .line 134
    const/16 v18, 0x283

    .line 135
    .line 136
    const/4 v6, 0x0

    .line 137
    const/4 v7, 0x0

    .line 138
    const/4 v8, 0x0

    .line 139
    const/4 v13, 0x0

    .line 140
    const/4 v14, 0x0

    .line 141
    invoke-static/range {v5 .. v18}, Lk30/e;->a(Lk30/e;Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;ZZLql0/g;Ler0/g;Llf0/i;I)Lk30/e;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 146
    .line 147
    .line 148
    return-void
.end method

.method public static k(Ljava/util/ArrayList;)Z
    .locals 1

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lj30/b;

    .line 23
    .line 24
    iget-object v0, v0, Lj30/b;->b:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Ljava/util/Collection;

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_1

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 37
    return p0
.end method


# virtual methods
.method public final j(Ljava/util/ArrayList;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const/4 v0, 0x0

    .line 6
    move v1, v0

    .line 7
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Lj30/b;

    .line 18
    .line 19
    iget-object v2, v2, Lj30/b;->b:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Ljava/util/Collection;

    .line 22
    .line 23
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    add-int/2addr v1, v2

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    iget-object p0, p0, Lk30/h;->m:Lij0/a;

    .line 30
    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    new-array p1, v0, [Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Ljj0/f;

    .line 36
    .line 37
    const v0, 0x7f12155d

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, v0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :cond_1
    new-array p1, v0, [Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Ljj0/f;

    .line 48
    .line 49
    const v0, 0x7f100034

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, v0, v1, p1}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public final l(II)Llx0/l;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    iget-object p0, p0, Lk30/h;->m:Lij0/a;

    .line 5
    .line 6
    check-cast p0, Ljj0/f;

    .line 7
    .line 8
    invoke-virtual {p0, p1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    new-instance p2, Llx0/l;

    .line 17
    .line 18
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-object p2
.end method

.method public final q(Lj30/b;)Lk30/d;
    .locals 2

    .line 1
    iget-object v0, p1, Lj30/b;->a:Lj30/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0x7f08039d

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const v0, 0x7f121565

    .line 20
    .line 21
    .line 22
    const v1, 0x7f080427

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    goto :goto_0

    .line 30
    :pswitch_1
    const v0, 0x7f121566

    .line 31
    .line 32
    .line 33
    const v1, 0x7f080506

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    goto :goto_0

    .line 41
    :pswitch_2
    const v0, 0x7f121564

    .line 42
    .line 43
    .line 44
    const v1, 0x7f0803f3

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    goto :goto_0

    .line 52
    :pswitch_3
    const v0, 0x7f121562

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    goto :goto_0

    .line 60
    :pswitch_4
    const v0, 0x7f121563

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    goto :goto_0

    .line 68
    :pswitch_5
    const v0, 0x7f121561

    .line 69
    .line 70
    .line 71
    const v1, 0x7f080365

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    goto :goto_0

    .line 79
    :pswitch_6
    const v0, 0x7f121560

    .line 80
    .line 81
    .line 82
    const v1, 0x7f0802eb

    .line 83
    .line 84
    .line 85
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    goto :goto_0

    .line 90
    :pswitch_7
    const v0, 0x7f12155f

    .line 91
    .line 92
    .line 93
    const v1, 0x7f08029d

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0, v0, v1}, Lk30/h;->l(II)Llx0/l;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    :goto_0
    iget-object v0, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v0, Ljava/lang/String;

    .line 103
    .line 104
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast p0, Ljava/lang/Number;

    .line 107
    .line 108
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    new-instance v1, Lk30/d;

    .line 113
    .line 114
    iget-object p1, p1, Lj30/b;->b:Ljava/lang/Object;

    .line 115
    .line 116
    invoke-direct {v1, p0, v0, p1}, Lk30/d;-><init>(ILjava/lang/String;Ljava/util/List;)V

    .line 117
    .line 118
    .line 119
    return-object v1

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
