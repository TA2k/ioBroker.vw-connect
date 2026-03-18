.class public final Lg4/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg4/b;


# instance fields
.field public final a:Lr4/o;

.field public final b:J

.field public final c:Lk4/x;

.field public final d:Lk4/t;

.field public final e:Lk4/u;

.field public final f:Lk4/n;

.field public final g:Ljava/lang/String;

.field public final h:J

.field public final i:Lr4/a;

.field public final j:Lr4/p;

.field public final k:Ln4/b;

.field public final l:J

.field public final m:Lr4/l;

.field public final n:Le3/m0;

.field public final o:Lg4/x;

.field public final p:Lg3/e;


# direct methods
.method public constructor <init>(JJLk4/x;Lk4/t;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;)V
    .locals 23

    move-wide/from16 v0, p1

    const-wide/16 v2, 0x10

    cmp-long v2, v0, v2

    if-eqz v2, :cond_0

    .line 1
    new-instance v2, Lr4/c;

    invoke-direct {v2, v0, v1}, Lr4/c;-><init>(J)V

    :goto_0
    move-object v4, v2

    goto :goto_1

    :cond_0
    sget-object v2, Lr4/n;->a:Lr4/n;

    goto :goto_0

    :goto_1
    const/4 v9, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    move-object/from16 v3, p0

    move-wide/from16 v5, p3

    move-object/from16 v7, p5

    move-object/from16 v8, p6

    move-object/from16 v10, p7

    move-object/from16 v11, p8

    move-wide/from16 v12, p9

    move-object/from16 v14, p11

    move-object/from16 v15, p12

    move-object/from16 v16, p13

    move-wide/from16 v17, p14

    move-object/from16 v19, p16

    move-object/from16 v20, p17

    .line 2
    invoke-direct/range {v3 .. v22}, Lg4/g0;-><init>(Lr4/o;JLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)V

    return-void
.end method

.method public constructor <init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V
    .locals 23

    move/from16 v0, p19

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 22
    sget-wide v1, Le3/s;->i:J

    move-wide v4, v1

    goto :goto_0

    :cond_0
    move-wide/from16 v4, p1

    :goto_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    .line 23
    sget-wide v1, Lt4/o;->c:J

    move-wide v6, v1

    goto :goto_1

    :cond_1
    move-wide/from16 v6, p3

    :goto_1
    and-int/lit8 v1, v0, 0x4

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    move-object v8, v2

    goto :goto_2

    :cond_2
    move-object/from16 v8, p5

    :goto_2
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_3

    move-object v9, v2

    goto :goto_3

    :cond_3
    move-object/from16 v9, p6

    :goto_3
    and-int/lit8 v1, v0, 0x10

    if-eqz v1, :cond_4

    move-object v10, v2

    goto :goto_4

    :cond_4
    move-object/from16 v10, p7

    :goto_4
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_5

    move-object v11, v2

    goto :goto_5

    :cond_5
    move-object/from16 v11, p8

    :goto_5
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_6

    move-object v12, v2

    goto :goto_6

    :cond_6
    move-object/from16 v12, p9

    :goto_6
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_7

    .line 24
    sget-wide v13, Lt4/o;->c:J

    goto :goto_7

    :cond_7
    move-wide/from16 v13, p10

    :goto_7
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_8

    move-object v15, v2

    goto :goto_8

    :cond_8
    move-object/from16 v15, p12

    :goto_8
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_9

    move-object/from16 v16, v2

    goto :goto_9

    :cond_9
    move-object/from16 v16, p13

    :goto_9
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_a

    move-object/from16 v17, v2

    goto :goto_a

    :cond_a
    move-object/from16 v17, p14

    :goto_a
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_b

    .line 25
    sget-wide v18, Le3/s;->i:J

    goto :goto_b

    :cond_b
    move-wide/from16 v18, p15

    :goto_b
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_c

    move-object/from16 v20, v2

    goto :goto_c

    :cond_c
    move-object/from16 v20, p17

    :goto_c
    and-int/lit16 v0, v0, 0x2000

    if-eqz v0, :cond_d

    move-object/from16 v21, v2

    goto :goto_d

    :cond_d
    move-object/from16 v21, p18

    :goto_d
    const/16 v22, 0x0

    move-object/from16 v3, p0

    .line 26
    invoke-direct/range {v3 .. v22}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;)V

    return-void
.end method

.method public constructor <init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;)V
    .locals 23

    move-wide/from16 v0, p1

    const-wide/16 v2, 0x10

    cmp-long v2, v0, v2

    if-eqz v2, :cond_0

    .line 3
    new-instance v2, Lr4/c;

    invoke-direct {v2, v0, v1}, Lr4/c;-><init>(J)V

    :goto_0
    move-object v4, v2

    goto :goto_1

    :cond_0
    sget-object v2, Lr4/n;->a:Lr4/n;

    goto :goto_0

    :goto_1
    const/16 v22, 0x0

    move-object/from16 v3, p0

    move-wide/from16 v5, p3

    move-object/from16 v7, p5

    move-object/from16 v8, p6

    move-object/from16 v9, p7

    move-object/from16 v10, p8

    move-object/from16 v11, p9

    move-wide/from16 v12, p10

    move-object/from16 v14, p12

    move-object/from16 v15, p13

    move-object/from16 v16, p14

    move-wide/from16 v17, p15

    move-object/from16 v19, p17

    move-object/from16 v20, p18

    move-object/from16 v21, p19

    .line 4
    invoke-direct/range {v3 .. v22}, Lg4/g0;-><init>(Lr4/o;JLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)V

    return-void
.end method

.method public constructor <init>(Lr4/o;JLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lg4/g0;->a:Lr4/o;

    .line 7
    iput-wide p2, p0, Lg4/g0;->b:J

    .line 8
    iput-object p4, p0, Lg4/g0;->c:Lk4/x;

    .line 9
    iput-object p5, p0, Lg4/g0;->d:Lk4/t;

    .line 10
    iput-object p6, p0, Lg4/g0;->e:Lk4/u;

    .line 11
    iput-object p7, p0, Lg4/g0;->f:Lk4/n;

    .line 12
    iput-object p8, p0, Lg4/g0;->g:Ljava/lang/String;

    .line 13
    iput-wide p9, p0, Lg4/g0;->h:J

    .line 14
    iput-object p11, p0, Lg4/g0;->i:Lr4/a;

    .line 15
    iput-object p12, p0, Lg4/g0;->j:Lr4/p;

    .line 16
    iput-object p13, p0, Lg4/g0;->k:Ln4/b;

    .line 17
    iput-wide p14, p0, Lg4/g0;->l:J

    move-object/from16 p1, p16

    .line 18
    iput-object p1, p0, Lg4/g0;->m:Lr4/l;

    move-object/from16 p1, p17

    .line 19
    iput-object p1, p0, Lg4/g0;->n:Le3/m0;

    move-object/from16 p1, p18

    .line 20
    iput-object p1, p0, Lg4/g0;->o:Lg4/x;

    move-object/from16 p1, p19

    .line 21
    iput-object p1, p0, Lg4/g0;->p:Lg3/e;

    return-void
.end method

.method public static a(Lg4/g0;JI)Lg4/g0;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    and-int/lit8 v1, p3, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v0, Lg4/g0;->a:Lr4/o;

    .line 8
    .line 9
    invoke-interface {v1}, Lr4/o;->a()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-wide/from16 v1, p1

    .line 15
    .line 16
    :goto_0
    iget-wide v5, v0, Lg4/g0;->b:J

    .line 17
    .line 18
    iget-object v7, v0, Lg4/g0;->c:Lk4/x;

    .line 19
    .line 20
    iget-object v8, v0, Lg4/g0;->d:Lk4/t;

    .line 21
    .line 22
    iget-object v9, v0, Lg4/g0;->e:Lk4/u;

    .line 23
    .line 24
    and-int/lit8 v3, p3, 0x20

    .line 25
    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    iget-object v3, v0, Lg4/g0;->f:Lk4/n;

    .line 29
    .line 30
    :goto_1
    move-object v10, v3

    .line 31
    goto :goto_2

    .line 32
    :cond_1
    const/4 v3, 0x0

    .line 33
    goto :goto_1

    .line 34
    :goto_2
    iget-object v11, v0, Lg4/g0;->g:Ljava/lang/String;

    .line 35
    .line 36
    iget-wide v12, v0, Lg4/g0;->h:J

    .line 37
    .line 38
    iget-object v14, v0, Lg4/g0;->i:Lr4/a;

    .line 39
    .line 40
    iget-object v15, v0, Lg4/g0;->j:Lr4/p;

    .line 41
    .line 42
    iget-object v3, v0, Lg4/g0;->k:Ln4/b;

    .line 43
    .line 44
    move-object/from16 v16, v3

    .line 45
    .line 46
    iget-wide v3, v0, Lg4/g0;->l:J

    .line 47
    .line 48
    move-wide/from16 v17, v3

    .line 49
    .line 50
    iget-object v3, v0, Lg4/g0;->m:Lr4/l;

    .line 51
    .line 52
    iget-object v4, v0, Lg4/g0;->n:Le3/m0;

    .line 53
    .line 54
    move-object/from16 v19, v3

    .line 55
    .line 56
    iget-object v3, v0, Lg4/g0;->o:Lg4/x;

    .line 57
    .line 58
    move-object/from16 v21, v3

    .line 59
    .line 60
    iget-object v3, v0, Lg4/g0;->p:Lg3/e;

    .line 61
    .line 62
    move-object/from16 v22, v3

    .line 63
    .line 64
    new-instance v3, Lg4/g0;

    .line 65
    .line 66
    iget-object v0, v0, Lg4/g0;->a:Lr4/o;

    .line 67
    .line 68
    move-object/from16 p1, v3

    .line 69
    .line 70
    move-object/from16 v20, v4

    .line 71
    .line 72
    invoke-interface {v0}, Lr4/o;->a()J

    .line 73
    .line 74
    .line 75
    move-result-wide v3

    .line 76
    invoke-static {v1, v2, v3, v4}, Le3/s;->c(JJ)Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-eqz v3, :cond_2

    .line 81
    .line 82
    :goto_3
    move-object/from16 v3, p1

    .line 83
    .line 84
    move-object v4, v0

    .line 85
    goto :goto_4

    .line 86
    :cond_2
    const-wide/16 v3, 0x10

    .line 87
    .line 88
    cmp-long v0, v1, v3

    .line 89
    .line 90
    if-eqz v0, :cond_3

    .line 91
    .line 92
    new-instance v0, Lr4/c;

    .line 93
    .line 94
    invoke-direct {v0, v1, v2}, Lr4/c;-><init>(J)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_3
    sget-object v0, Lr4/n;->a:Lr4/n;

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :goto_4
    invoke-direct/range {v3 .. v22}, Lg4/g0;-><init>(Lr4/o;JLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)V

    .line 102
    .line 103
    .line 104
    return-object v3
.end method


# virtual methods
.method public final b(Lg4/g0;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    iget-wide v1, p0, Lg4/g0;->b:J

    .line 6
    .line 7
    iget-wide v3, p1, Lg4/g0;->b:J

    .line 8
    .line 9
    invoke-static {v1, v2, v3, v4}, Lt4/o;->a(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    return v2

    .line 17
    :cond_1
    iget-object v1, p0, Lg4/g0;->c:Lk4/x;

    .line 18
    .line 19
    iget-object v3, p1, Lg4/g0;->c:Lk4/x;

    .line 20
    .line 21
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_2

    .line 26
    .line 27
    return v2

    .line 28
    :cond_2
    iget-object v1, p0, Lg4/g0;->d:Lk4/t;

    .line 29
    .line 30
    iget-object v3, p1, Lg4/g0;->d:Lk4/t;

    .line 31
    .line 32
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-nez v1, :cond_3

    .line 37
    .line 38
    return v2

    .line 39
    :cond_3
    iget-object v1, p0, Lg4/g0;->e:Lk4/u;

    .line 40
    .line 41
    iget-object v3, p1, Lg4/g0;->e:Lk4/u;

    .line 42
    .line 43
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-nez v1, :cond_4

    .line 48
    .line 49
    return v2

    .line 50
    :cond_4
    iget-object v1, p0, Lg4/g0;->f:Lk4/n;

    .line 51
    .line 52
    iget-object v3, p1, Lg4/g0;->f:Lk4/n;

    .line 53
    .line 54
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-nez v1, :cond_5

    .line 59
    .line 60
    return v2

    .line 61
    :cond_5
    iget-object v1, p0, Lg4/g0;->g:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v3, p1, Lg4/g0;->g:Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-nez v1, :cond_6

    .line 70
    .line 71
    return v2

    .line 72
    :cond_6
    iget-wide v3, p0, Lg4/g0;->h:J

    .line 73
    .line 74
    iget-wide v5, p1, Lg4/g0;->h:J

    .line 75
    .line 76
    invoke-static {v3, v4, v5, v6}, Lt4/o;->a(JJ)Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-nez v1, :cond_7

    .line 81
    .line 82
    return v2

    .line 83
    :cond_7
    iget-object v1, p0, Lg4/g0;->i:Lr4/a;

    .line 84
    .line 85
    iget-object v3, p1, Lg4/g0;->i:Lr4/a;

    .line 86
    .line 87
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-nez v1, :cond_8

    .line 92
    .line 93
    return v2

    .line 94
    :cond_8
    iget-object v1, p0, Lg4/g0;->j:Lr4/p;

    .line 95
    .line 96
    iget-object v3, p1, Lg4/g0;->j:Lr4/p;

    .line 97
    .line 98
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    if-nez v1, :cond_9

    .line 103
    .line 104
    return v2

    .line 105
    :cond_9
    iget-object v1, p0, Lg4/g0;->k:Ln4/b;

    .line 106
    .line 107
    iget-object v3, p1, Lg4/g0;->k:Ln4/b;

    .line 108
    .line 109
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    if-nez v1, :cond_a

    .line 114
    .line 115
    return v2

    .line 116
    :cond_a
    iget-wide v3, p0, Lg4/g0;->l:J

    .line 117
    .line 118
    iget-wide v5, p1, Lg4/g0;->l:J

    .line 119
    .line 120
    invoke-static {v3, v4, v5, v6}, Le3/s;->c(JJ)Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-nez v1, :cond_b

    .line 125
    .line 126
    return v2

    .line 127
    :cond_b
    iget-object p0, p0, Lg4/g0;->o:Lg4/x;

    .line 128
    .line 129
    iget-object p1, p1, Lg4/g0;->o:Lg4/x;

    .line 130
    .line 131
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    if-nez p0, :cond_c

    .line 136
    .line 137
    return v2

    .line 138
    :cond_c
    return v0
.end method

.method public final c(Lg4/g0;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lg4/g0;->a:Lr4/o;

    .line 2
    .line 3
    iget-object v1, p1, Lg4/g0;->a:Lr4/o;

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    return v1

    .line 13
    :cond_0
    iget-object v0, p0, Lg4/g0;->m:Lr4/l;

    .line 14
    .line 15
    iget-object v2, p1, Lg4/g0;->m:Lr4/l;

    .line 16
    .line 17
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    return v1

    .line 24
    :cond_1
    iget-object v0, p0, Lg4/g0;->n:Le3/m0;

    .line 25
    .line 26
    iget-object v2, p1, Lg4/g0;->n:Le3/m0;

    .line 27
    .line 28
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    return v1

    .line 35
    :cond_2
    iget-object p0, p0, Lg4/g0;->p:Lg3/e;

    .line 36
    .line 37
    iget-object p1, p1, Lg4/g0;->p:Lg3/e;

    .line 38
    .line 39
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_3

    .line 44
    .line 45
    return v1

    .line 46
    :cond_3
    const/4 p0, 0x1

    .line 47
    return p0
.end method

.method public final d(Lg4/g0;)Lg4/g0;
    .locals 25

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    iget-object v1, v0, Lg4/g0;->a:Lr4/o;

    .line 7
    .line 8
    invoke-interface {v1}, Lr4/o;->a()J

    .line 9
    .line 10
    .line 11
    move-result-wide v3

    .line 12
    invoke-interface {v1}, Lr4/o;->c()Le3/p;

    .line 13
    .line 14
    .line 15
    move-result-object v5

    .line 16
    invoke-interface {v1}, Lr4/o;->b()F

    .line 17
    .line 18
    .line 19
    move-result v6

    .line 20
    iget-wide v7, v0, Lg4/g0;->b:J

    .line 21
    .line 22
    iget-object v9, v0, Lg4/g0;->c:Lk4/x;

    .line 23
    .line 24
    iget-object v10, v0, Lg4/g0;->d:Lk4/t;

    .line 25
    .line 26
    iget-object v11, v0, Lg4/g0;->e:Lk4/u;

    .line 27
    .line 28
    iget-object v12, v0, Lg4/g0;->f:Lk4/n;

    .line 29
    .line 30
    iget-object v13, v0, Lg4/g0;->g:Ljava/lang/String;

    .line 31
    .line 32
    iget-wide v14, v0, Lg4/g0;->h:J

    .line 33
    .line 34
    iget-object v1, v0, Lg4/g0;->i:Lr4/a;

    .line 35
    .line 36
    iget-object v2, v0, Lg4/g0;->j:Lr4/p;

    .line 37
    .line 38
    move-object/from16 v16, v1

    .line 39
    .line 40
    iget-object v1, v0, Lg4/g0;->k:Ln4/b;

    .line 41
    .line 42
    move-object/from16 v18, v1

    .line 43
    .line 44
    move-object/from16 v17, v2

    .line 45
    .line 46
    iget-wide v1, v0, Lg4/g0;->l:J

    .line 47
    .line 48
    move-wide/from16 v19, v1

    .line 49
    .line 50
    iget-object v1, v0, Lg4/g0;->m:Lr4/l;

    .line 51
    .line 52
    iget-object v2, v0, Lg4/g0;->n:Le3/m0;

    .line 53
    .line 54
    move-object/from16 v21, v1

    .line 55
    .line 56
    iget-object v1, v0, Lg4/g0;->o:Lg4/x;

    .line 57
    .line 58
    iget-object v0, v0, Lg4/g0;->p:Lg3/e;

    .line 59
    .line 60
    move-object/from16 v24, v0

    .line 61
    .line 62
    move-object/from16 v23, v1

    .line 63
    .line 64
    move-object/from16 v22, v2

    .line 65
    .line 66
    move-object/from16 v2, p0

    .line 67
    .line 68
    invoke-static/range {v2 .. v24}, Lg4/h0;->a(Lg4/g0;JLe3/p;FJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)Lg4/g0;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lg4/g0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lg4/g0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg4/g0;->b(Lg4/g0;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lg4/g0;->c(Lg4/g0;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_2

    .line 24
    .line 25
    return v0

    .line 26
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 7

    .line 1
    iget-object v0, p0, Lg4/g0;->a:Lr4/o;

    .line 2
    .line 3
    invoke-interface {v0}, Lr4/o;->a()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    sget v3, Le3/s;->j:I

    .line 8
    .line 9
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/16 v2, 0x1f

    .line 14
    .line 15
    mul-int/2addr v1, v2

    .line 16
    invoke-interface {v0}, Lr4/o;->c()Le3/p;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const/4 v4, 0x0

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v3, v4

    .line 29
    :goto_0
    add-int/2addr v1, v3

    .line 30
    mul-int/2addr v1, v2

    .line 31
    invoke-interface {v0}, Lr4/o;->b()F

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    add-int/2addr v0, v1

    .line 40
    mul-int/2addr v0, v2

    .line 41
    sget-object v1, Lt4/o;->b:[Lt4/p;

    .line 42
    .line 43
    iget-wide v5, p0, Lg4/g0;->b:J

    .line 44
    .line 45
    invoke-static {v5, v6, v0, v2}, La7/g0;->f(JII)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    iget-object v1, p0, Lg4/g0;->c:Lk4/x;

    .line 50
    .line 51
    if-eqz v1, :cond_1

    .line 52
    .line 53
    iget v1, v1, Lk4/x;->d:I

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    move v1, v4

    .line 57
    :goto_1
    add-int/2addr v0, v1

    .line 58
    mul-int/2addr v0, v2

    .line 59
    iget-object v1, p0, Lg4/g0;->d:Lk4/t;

    .line 60
    .line 61
    if-eqz v1, :cond_2

    .line 62
    .line 63
    iget v1, v1, Lk4/t;->a:I

    .line 64
    .line 65
    invoke-static {v1}, Ljava/lang/Integer;->hashCode(I)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    goto :goto_2

    .line 70
    :cond_2
    move v1, v4

    .line 71
    :goto_2
    add-int/2addr v0, v1

    .line 72
    mul-int/2addr v0, v2

    .line 73
    iget-object v1, p0, Lg4/g0;->e:Lk4/u;

    .line 74
    .line 75
    if-eqz v1, :cond_3

    .line 76
    .line 77
    iget v1, v1, Lk4/u;->a:I

    .line 78
    .line 79
    invoke-static {v1}, Ljava/lang/Integer;->hashCode(I)I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    goto :goto_3

    .line 84
    :cond_3
    move v1, v4

    .line 85
    :goto_3
    add-int/2addr v0, v1

    .line 86
    mul-int/2addr v0, v2

    .line 87
    iget-object v1, p0, Lg4/g0;->f:Lk4/n;

    .line 88
    .line 89
    if-eqz v1, :cond_4

    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    goto :goto_4

    .line 96
    :cond_4
    move v1, v4

    .line 97
    :goto_4
    add-int/2addr v0, v1

    .line 98
    mul-int/2addr v0, v2

    .line 99
    iget-object v1, p0, Lg4/g0;->g:Ljava/lang/String;

    .line 100
    .line 101
    if-eqz v1, :cond_5

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    goto :goto_5

    .line 108
    :cond_5
    move v1, v4

    .line 109
    :goto_5
    add-int/2addr v0, v1

    .line 110
    mul-int/2addr v0, v2

    .line 111
    iget-wide v5, p0, Lg4/g0;->h:J

    .line 112
    .line 113
    invoke-static {v5, v6, v0, v2}, La7/g0;->f(JII)I

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    iget-object v1, p0, Lg4/g0;->i:Lr4/a;

    .line 118
    .line 119
    if-eqz v1, :cond_6

    .line 120
    .line 121
    iget v1, v1, Lr4/a;->a:F

    .line 122
    .line 123
    invoke-static {v1}, Ljava/lang/Float;->hashCode(F)I

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    goto :goto_6

    .line 128
    :cond_6
    move v1, v4

    .line 129
    :goto_6
    add-int/2addr v0, v1

    .line 130
    mul-int/2addr v0, v2

    .line 131
    iget-object v1, p0, Lg4/g0;->j:Lr4/p;

    .line 132
    .line 133
    if-eqz v1, :cond_7

    .line 134
    .line 135
    invoke-virtual {v1}, Lr4/p;->hashCode()I

    .line 136
    .line 137
    .line 138
    move-result v1

    .line 139
    goto :goto_7

    .line 140
    :cond_7
    move v1, v4

    .line 141
    :goto_7
    add-int/2addr v0, v1

    .line 142
    mul-int/2addr v0, v2

    .line 143
    iget-object v1, p0, Lg4/g0;->k:Ln4/b;

    .line 144
    .line 145
    if-eqz v1, :cond_8

    .line 146
    .line 147
    iget-object v1, v1, Ln4/b;->d:Ljava/util/List;

    .line 148
    .line 149
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    goto :goto_8

    .line 154
    :cond_8
    move v1, v4

    .line 155
    :goto_8
    add-int/2addr v0, v1

    .line 156
    mul-int/2addr v0, v2

    .line 157
    iget-wide v5, p0, Lg4/g0;->l:J

    .line 158
    .line 159
    invoke-static {v5, v6, v0, v2}, La7/g0;->f(JII)I

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    iget-object v1, p0, Lg4/g0;->m:Lr4/l;

    .line 164
    .line 165
    if-eqz v1, :cond_9

    .line 166
    .line 167
    iget v1, v1, Lr4/l;->a:I

    .line 168
    .line 169
    goto :goto_9

    .line 170
    :cond_9
    move v1, v4

    .line 171
    :goto_9
    add-int/2addr v0, v1

    .line 172
    mul-int/2addr v0, v2

    .line 173
    iget-object v1, p0, Lg4/g0;->n:Le3/m0;

    .line 174
    .line 175
    if-eqz v1, :cond_a

    .line 176
    .line 177
    invoke-virtual {v1}, Le3/m0;->hashCode()I

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    goto :goto_a

    .line 182
    :cond_a
    move v1, v4

    .line 183
    :goto_a
    add-int/2addr v0, v1

    .line 184
    mul-int/2addr v0, v2

    .line 185
    iget-object v1, p0, Lg4/g0;->o:Lg4/x;

    .line 186
    .line 187
    if-eqz v1, :cond_b

    .line 188
    .line 189
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    goto :goto_b

    .line 194
    :cond_b
    move v1, v4

    .line 195
    :goto_b
    add-int/2addr v0, v1

    .line 196
    mul-int/2addr v0, v2

    .line 197
    iget-object p0, p0, Lg4/g0;->p:Lg3/e;

    .line 198
    .line 199
    if-eqz p0, :cond_c

    .line 200
    .line 201
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    :cond_c
    add-int/2addr v0, v4

    .line 206
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SpanStyle(color="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lg4/g0;->a:Lr4/o;

    .line 9
    .line 10
    invoke-interface {v1}, Lr4/o;->a()J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    invoke-static {v2, v3}, Le3/s;->i(J)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v2, ", brush="

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-interface {v1}, Lr4/o;->c()Le3/p;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v2, ", alpha="

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-interface {v1}, Lr4/o;->b()F

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, ", fontSize="

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-wide v1, p0, Lg4/g0;->b:J

    .line 51
    .line 52
    invoke-static {v1, v2}, Lt4/o;->d(J)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", fontWeight="

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    iget-object v1, p0, Lg4/g0;->c:Lk4/x;

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v1, ", fontStyle="

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    iget-object v1, p0, Lg4/g0;->d:Lk4/t;

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    const-string v1, ", fontSynthesis="

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    iget-object v1, p0, Lg4/g0;->e:Lk4/u;

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v1, ", fontFamily="

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    iget-object v1, p0, Lg4/g0;->f:Lk4/n;

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ", fontFeatureSettings="

    .line 100
    .line 101
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    iget-object v1, p0, Lg4/g0;->g:Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v1, ", letterSpacing="

    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    iget-wide v1, p0, Lg4/g0;->h:J

    .line 115
    .line 116
    invoke-static {v1, v2}, Lt4/o;->d(J)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", baselineShift="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    iget-object v1, p0, Lg4/g0;->i:Lr4/a;

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v1, ", textGeometricTransform="

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    iget-object v1, p0, Lg4/g0;->j:Lr4/p;

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    const-string v1, ", localeList="

    .line 144
    .line 145
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    iget-object v1, p0, Lg4/g0;->k:Ln4/b;

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v1, ", background="

    .line 154
    .line 155
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    iget-wide v1, p0, Lg4/g0;->l:J

    .line 159
    .line 160
    const-string v3, ", textDecoration="

    .line 161
    .line 162
    invoke-static {v1, v2, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->x(JLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 163
    .line 164
    .line 165
    iget-object v1, p0, Lg4/g0;->m:Lr4/l;

    .line 166
    .line 167
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    const-string v1, ", shadow="

    .line 171
    .line 172
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    iget-object v1, p0, Lg4/g0;->n:Le3/m0;

    .line 176
    .line 177
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    const-string v1, ", platformStyle="

    .line 181
    .line 182
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    iget-object v1, p0, Lg4/g0;->o:Lg4/x;

    .line 186
    .line 187
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 188
    .line 189
    .line 190
    const-string v1, ", drawStyle="

    .line 191
    .line 192
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    iget-object p0, p0, Lg4/g0;->p:Lg3/e;

    .line 196
    .line 197
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    const/16 p0, 0x29

    .line 201
    .line 202
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    return-object p0
.end method
