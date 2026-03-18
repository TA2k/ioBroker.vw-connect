.class public final synthetic Lxw0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lxw0/b;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lxw0/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lxw0/b;->a:Lxw0/b;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "io.ktor.util.date.GMTDate"

    .line 11
    .line 12
    const/16 v3, 0x9

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "seconds"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "minutes"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "hours"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "dayOfWeek"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "dayOfMonth"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "dayOfYear"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "month"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "year"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    const-string v0, "timestamp"

    .line 59
    .line 60
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 61
    .line 62
    .line 63
    sput-object v1, Lxw0/b;->descriptor:Lsz0/g;

    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lxw0/d;->m:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0x9

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    sget-object v1, Luz0/k0;->a:Luz0/k0;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    aput-object v1, v0, v2

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    aput-object v1, v0, v2

    .line 14
    .line 15
    const/4 v2, 0x2

    .line 16
    aput-object v1, v0, v2

    .line 17
    .line 18
    const/4 v2, 0x3

    .line 19
    aget-object v3, p0, v2

    .line 20
    .line 21
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    aput-object v3, v0, v2

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    aput-object v1, v0, v2

    .line 29
    .line 30
    const/4 v2, 0x5

    .line 31
    aput-object v1, v0, v2

    .line 32
    .line 33
    const/4 v2, 0x6

    .line 34
    aget-object p0, p0, v2

    .line 35
    .line 36
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    aput-object p0, v0, v2

    .line 41
    .line 42
    const/4 p0, 0x7

    .line 43
    aput-object v1, v0, p0

    .line 44
    .line 45
    const/16 p0, 0x8

    .line 46
    .line 47
    sget-object v1, Luz0/q0;->a:Luz0/q0;

    .line 48
    .line 49
    aput-object v1, v0, p0

    .line 50
    .line 51
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 20

    .line 1
    sget-object v0, Lxw0/b;->descriptor:Lsz0/g;

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Lxw0/d;->m:[Llx0/i;

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v5, 0x0

    .line 14
    const-wide/16 v6, 0x0

    .line 15
    .line 16
    move v9, v4

    .line 17
    move v10, v9

    .line 18
    move v11, v10

    .line 19
    move v12, v11

    .line 20
    move v14, v12

    .line 21
    move v15, v14

    .line 22
    move/from16 v17, v15

    .line 23
    .line 24
    move-object v13, v5

    .line 25
    move-wide/from16 v18, v6

    .line 26
    .line 27
    move v6, v3

    .line 28
    :goto_0
    if-eqz v6, :cond_0

    .line 29
    .line 30
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    packed-switch v7, :pswitch_data_0

    .line 35
    .line 36
    .line 37
    new-instance v0, Lqz0/k;

    .line 38
    .line 39
    invoke-direct {v0, v7}, Lqz0/k;-><init>(I)V

    .line 40
    .line 41
    .line 42
    throw v0

    .line 43
    :pswitch_0
    const/16 v7, 0x8

    .line 44
    .line 45
    invoke-interface {v1, v0, v7}, Ltz0/a;->A(Lsz0/g;I)J

    .line 46
    .line 47
    .line 48
    move-result-wide v18

    .line 49
    or-int/lit16 v9, v9, 0x100

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_1
    const/4 v7, 0x7

    .line 53
    invoke-interface {v1, v0, v7}, Ltz0/a;->l(Lsz0/g;I)I

    .line 54
    .line 55
    .line 56
    move-result v17

    .line 57
    or-int/lit16 v9, v9, 0x80

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :pswitch_2
    const/4 v7, 0x6

    .line 61
    aget-object v8, v2, v7

    .line 62
    .line 63
    invoke-interface {v8}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v8

    .line 67
    check-cast v8, Lqz0/a;

    .line 68
    .line 69
    invoke-interface {v1, v0, v7, v8, v5}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Lxw0/e;

    .line 74
    .line 75
    or-int/lit8 v9, v9, 0x40

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_3
    const/4 v7, 0x5

    .line 79
    invoke-interface {v1, v0, v7}, Ltz0/a;->l(Lsz0/g;I)I

    .line 80
    .line 81
    .line 82
    move-result v15

    .line 83
    or-int/lit8 v9, v9, 0x20

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :pswitch_4
    const/4 v7, 0x4

    .line 87
    invoke-interface {v1, v0, v7}, Ltz0/a;->l(Lsz0/g;I)I

    .line 88
    .line 89
    .line 90
    move-result v14

    .line 91
    or-int/lit8 v9, v9, 0x10

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_5
    const/4 v7, 0x3

    .line 95
    aget-object v8, v2, v7

    .line 96
    .line 97
    invoke-interface {v8}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    check-cast v8, Lqz0/a;

    .line 102
    .line 103
    invoke-interface {v1, v0, v7, v8, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    move-object v13, v7

    .line 108
    check-cast v13, Lxw0/f;

    .line 109
    .line 110
    or-int/lit8 v9, v9, 0x8

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :pswitch_6
    const/4 v7, 0x2

    .line 114
    invoke-interface {v1, v0, v7}, Ltz0/a;->l(Lsz0/g;I)I

    .line 115
    .line 116
    .line 117
    move-result v12

    .line 118
    or-int/lit8 v9, v9, 0x4

    .line 119
    .line 120
    goto :goto_0

    .line 121
    :pswitch_7
    invoke-interface {v1, v0, v3}, Ltz0/a;->l(Lsz0/g;I)I

    .line 122
    .line 123
    .line 124
    move-result v11

    .line 125
    or-int/lit8 v9, v9, 0x2

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :pswitch_8
    invoke-interface {v1, v0, v4}, Ltz0/a;->l(Lsz0/g;I)I

    .line 129
    .line 130
    .line 131
    move-result v10

    .line 132
    or-int/lit8 v9, v9, 0x1

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :pswitch_9
    move v6, v4

    .line 136
    goto :goto_0

    .line 137
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 138
    .line 139
    .line 140
    new-instance v8, Lxw0/d;

    .line 141
    .line 142
    move-object/from16 v16, v5

    .line 143
    .line 144
    invoke-direct/range {v8 .. v19}, Lxw0/d;-><init>(IIIILxw0/f;IILxw0/e;IJ)V

    .line 145
    .line 146
    .line 147
    return-object v8

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_9
        :pswitch_8
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

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lxw0/b;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lxw0/d;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lxw0/b;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lxw0/d;->m:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    iget v2, p2, Lxw0/d;->d:I

    .line 18
    .line 19
    invoke-interface {p1, v1, v2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 20
    .line 21
    .line 22
    const/4 v1, 0x1

    .line 23
    iget v2, p2, Lxw0/d;->e:I

    .line 24
    .line 25
    invoke-interface {p1, v1, v2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x2

    .line 29
    iget v2, p2, Lxw0/d;->f:I

    .line 30
    .line 31
    invoke-interface {p1, v1, v2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 32
    .line 33
    .line 34
    const/4 v1, 0x3

    .line 35
    aget-object v2, v0, v1

    .line 36
    .line 37
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v2, Lqz0/a;

    .line 42
    .line 43
    iget-object v3, p2, Lxw0/d;->g:Lxw0/f;

    .line 44
    .line 45
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    const/4 v1, 0x4

    .line 49
    iget v2, p2, Lxw0/d;->h:I

    .line 50
    .line 51
    invoke-interface {p1, v1, v2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 52
    .line 53
    .line 54
    const/4 v1, 0x5

    .line 55
    iget v2, p2, Lxw0/d;->i:I

    .line 56
    .line 57
    invoke-interface {p1, v1, v2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 58
    .line 59
    .line 60
    const/4 v1, 0x6

    .line 61
    aget-object v0, v0, v1

    .line 62
    .line 63
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    check-cast v0, Lqz0/a;

    .line 68
    .line 69
    iget-object v2, p2, Lxw0/d;->j:Lxw0/e;

    .line 70
    .line 71
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const/4 v0, 0x7

    .line 75
    iget v1, p2, Lxw0/d;->k:I

    .line 76
    .line 77
    invoke-interface {p1, v0, v1, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 78
    .line 79
    .line 80
    const/16 v0, 0x8

    .line 81
    .line 82
    iget-wide v1, p2, Lxw0/d;->l:J

    .line 83
    .line 84
    invoke-interface {p1, p0, v0, v1, v2}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 85
    .line 86
    .line 87
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 88
    .line 89
    .line 90
    return-void
.end method
