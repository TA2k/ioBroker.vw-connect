.class public final Luj/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lce/k;


# static fields
.field public static final a:Luj/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luj/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luj/i;->a:Luj/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final X(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 27

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "event"

    .line 9
    .line 10
    move-object/from16 v4, p2

    .line 11
    .line 12
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    move-object/from16 v0, p3

    .line 16
    .line 17
    check-cast v0, Ll2/t;

    .line 18
    .line 19
    const v1, -0x771e9762

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    and-int/lit8 v1, p4, 0x1

    .line 26
    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v2, 0x0

    .line 32
    :goto_0
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lj91/f;

    .line 45
    .line 46
    invoke-virtual {v1}, Lj91/f;->i()Lg4/p0;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    const/16 v25, 0x0

    .line 51
    .line 52
    const v26, 0xfffc

    .line 53
    .line 54
    .line 55
    const-string v5, "Not yet implemented"

    .line 56
    .line 57
    const/4 v7, 0x0

    .line 58
    const-wide/16 v8, 0x0

    .line 59
    .line 60
    const-wide/16 v10, 0x0

    .line 61
    .line 62
    const/4 v12, 0x0

    .line 63
    const-wide/16 v13, 0x0

    .line 64
    .line 65
    const/4 v15, 0x0

    .line 66
    const/16 v16, 0x0

    .line 67
    .line 68
    const-wide/16 v17, 0x0

    .line 69
    .line 70
    const/16 v19, 0x0

    .line 71
    .line 72
    const/16 v20, 0x0

    .line 73
    .line 74
    const/16 v21, 0x0

    .line 75
    .line 76
    const/16 v22, 0x0

    .line 77
    .line 78
    const/16 v24, 0x6

    .line 79
    .line 80
    move-object/from16 v23, v0

    .line 81
    .line 82
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    move-object/from16 v23, v0

    .line 87
    .line 88
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_1
    invoke-virtual/range {v23 .. v23}, Ll2/t;->s()Ll2/u1;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    if-eqz v0, :cond_2

    .line 96
    .line 97
    new-instance v1, Luj/h;

    .line 98
    .line 99
    const/4 v6, 0x1

    .line 100
    move-object/from16 v2, p0

    .line 101
    .line 102
    move/from16 v5, p4

    .line 103
    .line 104
    invoke-direct/range {v1 .. v6}, Luj/h;-><init>(Luj/i;Llc/q;Lay0/k;II)V

    .line 105
    .line 106
    .line 107
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 108
    .line 109
    :cond_2
    return-void
.end method

.method public final y(Llc/q;Lay0/k;Ll2/o;I)V
    .locals 27

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "event"

    .line 9
    .line 10
    move-object/from16 v4, p2

    .line 11
    .line 12
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    move-object/from16 v0, p3

    .line 16
    .line 17
    check-cast v0, Ll2/t;

    .line 18
    .line 19
    const v1, -0x47dff5ed

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    and-int/lit8 v1, p4, 0x1

    .line 26
    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v2, 0x0

    .line 32
    :goto_0
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lj91/f;

    .line 45
    .line 46
    invoke-virtual {v1}, Lj91/f;->i()Lg4/p0;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    const/16 v25, 0x0

    .line 51
    .line 52
    const v26, 0xfffc

    .line 53
    .line 54
    .line 55
    const-string v5, "Not yet implemented"

    .line 56
    .line 57
    const/4 v7, 0x0

    .line 58
    const-wide/16 v8, 0x0

    .line 59
    .line 60
    const-wide/16 v10, 0x0

    .line 61
    .line 62
    const/4 v12, 0x0

    .line 63
    const-wide/16 v13, 0x0

    .line 64
    .line 65
    const/4 v15, 0x0

    .line 66
    const/16 v16, 0x0

    .line 67
    .line 68
    const-wide/16 v17, 0x0

    .line 69
    .line 70
    const/16 v19, 0x0

    .line 71
    .line 72
    const/16 v20, 0x0

    .line 73
    .line 74
    const/16 v21, 0x0

    .line 75
    .line 76
    const/16 v22, 0x0

    .line 77
    .line 78
    const/16 v24, 0x6

    .line 79
    .line 80
    move-object/from16 v23, v0

    .line 81
    .line 82
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    move-object/from16 v23, v0

    .line 87
    .line 88
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_1
    invoke-virtual/range {v23 .. v23}, Ll2/t;->s()Ll2/u1;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    if-eqz v0, :cond_2

    .line 96
    .line 97
    new-instance v1, Luj/h;

    .line 98
    .line 99
    const/4 v6, 0x0

    .line 100
    move-object/from16 v2, p0

    .line 101
    .line 102
    move/from16 v5, p4

    .line 103
    .line 104
    invoke-direct/range {v1 .. v6}, Luj/h;-><init>(Luj/i;Llc/q;Lay0/k;II)V

    .line 105
    .line 106
    .line 107
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 108
    .line 109
    :cond_2
    return-void
.end method
