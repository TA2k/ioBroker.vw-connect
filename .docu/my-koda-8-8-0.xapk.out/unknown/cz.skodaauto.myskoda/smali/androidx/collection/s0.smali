.class public final Landroidx/collection/s0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Landroidx/collection/o0;

.field public f:Landroidx/collection/t0;

.field public g:[J

.field public h:I

.field public i:I

.field public j:I

.field public k:I

.field public l:J

.field public m:I

.field public synthetic n:Ljava/lang/Object;

.field public final synthetic o:Landroidx/collection/t0;

.field public final synthetic p:Landroidx/collection/o0;


# direct methods
.method public constructor <init>(Landroidx/collection/t0;Landroidx/collection/o0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/collection/s0;->o:Landroidx/collection/t0;

    .line 2
    .line 3
    iput-object p2, p0, Landroidx/collection/s0;->p:Landroidx/collection/o0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Landroidx/collection/s0;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/collection/s0;->o:Landroidx/collection/t0;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/s0;->p:Landroidx/collection/o0;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Landroidx/collection/s0;-><init>(Landroidx/collection/t0;Landroidx/collection/o0;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Landroidx/collection/s0;->n:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lky0/k;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Landroidx/collection/s0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Landroidx/collection/s0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Landroidx/collection/s0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Landroidx/collection/s0;->m:I

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/16 v4, 0x8

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    if-ne v2, v5, :cond_0

    .line 14
    .line 15
    iget v2, v0, Landroidx/collection/s0;->k:I

    .line 16
    .line 17
    iget v6, v0, Landroidx/collection/s0;->j:I

    .line 18
    .line 19
    iget-wide v7, v0, Landroidx/collection/s0;->l:J

    .line 20
    .line 21
    iget v9, v0, Landroidx/collection/s0;->i:I

    .line 22
    .line 23
    iget v10, v0, Landroidx/collection/s0;->h:I

    .line 24
    .line 25
    iget-object v11, v0, Landroidx/collection/s0;->g:[J

    .line 26
    .line 27
    iget-object v12, v0, Landroidx/collection/s0;->f:Landroidx/collection/t0;

    .line 28
    .line 29
    iget-object v13, v0, Landroidx/collection/s0;->e:Landroidx/collection/o0;

    .line 30
    .line 31
    iget-object v14, v0, Landroidx/collection/s0;->n:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v14, Lky0/k;

    .line 34
    .line 35
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto/16 :goto_2

    .line 39
    .line 40
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v0

    .line 48
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object v2, v0, Landroidx/collection/s0;->n:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v2, Lky0/k;

    .line 54
    .line 55
    iget-object v6, v0, Landroidx/collection/s0;->o:Landroidx/collection/t0;

    .line 56
    .line 57
    iget-object v7, v6, Landroidx/collection/t0;->e:Landroidx/collection/r0;

    .line 58
    .line 59
    iget-object v7, v7, Landroidx/collection/r0;->a:[J

    .line 60
    .line 61
    array-length v8, v7

    .line 62
    add-int/lit8 v8, v8, -0x2

    .line 63
    .line 64
    if-ltz v8, :cond_5

    .line 65
    .line 66
    iget-object v9, v0, Landroidx/collection/s0;->p:Landroidx/collection/o0;

    .line 67
    .line 68
    move v10, v3

    .line 69
    :goto_0
    aget-wide v11, v7, v10

    .line 70
    .line 71
    not-long v13, v11

    .line 72
    const/4 v15, 0x7

    .line 73
    shl-long/2addr v13, v15

    .line 74
    and-long/2addr v13, v11

    .line 75
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    and-long/2addr v13, v15

    .line 81
    cmp-long v13, v13, v15

    .line 82
    .line 83
    if-eqz v13, :cond_4

    .line 84
    .line 85
    sub-int v13, v10, v8

    .line 86
    .line 87
    not-int v13, v13

    .line 88
    ushr-int/lit8 v13, v13, 0x1f

    .line 89
    .line 90
    rsub-int/lit8 v13, v13, 0x8

    .line 91
    .line 92
    move-object v14, v2

    .line 93
    move v2, v3

    .line 94
    move-wide/from16 v19, v11

    .line 95
    .line 96
    move-object v12, v6

    .line 97
    move-object v11, v7

    .line 98
    move v6, v13

    .line 99
    move-object v13, v9

    .line 100
    move v9, v10

    .line 101
    move v10, v8

    .line 102
    move-wide/from16 v7, v19

    .line 103
    .line 104
    :goto_1
    if-ge v2, v6, :cond_3

    .line 105
    .line 106
    const-wide/16 v15, 0xff

    .line 107
    .line 108
    and-long/2addr v15, v7

    .line 109
    const-wide/16 v17, 0x80

    .line 110
    .line 111
    cmp-long v15, v15, v17

    .line 112
    .line 113
    if-gez v15, :cond_2

    .line 114
    .line 115
    shl-int/lit8 v3, v9, 0x3

    .line 116
    .line 117
    add-int/2addr v3, v2

    .line 118
    iput v3, v13, Landroidx/collection/o0;->e:I

    .line 119
    .line 120
    iget-object v4, v12, Landroidx/collection/t0;->e:Landroidx/collection/r0;

    .line 121
    .line 122
    iget-object v4, v4, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 123
    .line 124
    aget-object v3, v4, v3

    .line 125
    .line 126
    iput-object v14, v0, Landroidx/collection/s0;->n:Ljava/lang/Object;

    .line 127
    .line 128
    iput-object v13, v0, Landroidx/collection/s0;->e:Landroidx/collection/o0;

    .line 129
    .line 130
    iput-object v12, v0, Landroidx/collection/s0;->f:Landroidx/collection/t0;

    .line 131
    .line 132
    iput-object v11, v0, Landroidx/collection/s0;->g:[J

    .line 133
    .line 134
    iput v10, v0, Landroidx/collection/s0;->h:I

    .line 135
    .line 136
    iput v9, v0, Landroidx/collection/s0;->i:I

    .line 137
    .line 138
    iput-wide v7, v0, Landroidx/collection/s0;->l:J

    .line 139
    .line 140
    iput v6, v0, Landroidx/collection/s0;->j:I

    .line 141
    .line 142
    iput v2, v0, Landroidx/collection/s0;->k:I

    .line 143
    .line 144
    iput v5, v0, Landroidx/collection/s0;->m:I

    .line 145
    .line 146
    invoke-virtual {v14, v3, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 147
    .line 148
    .line 149
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 150
    .line 151
    return-object v1

    .line 152
    :cond_2
    :goto_2
    shr-long/2addr v7, v4

    .line 153
    add-int/2addr v2, v5

    .line 154
    goto :goto_1

    .line 155
    :cond_3
    if-ne v6, v4, :cond_5

    .line 156
    .line 157
    move v8, v10

    .line 158
    move-object v7, v11

    .line 159
    move-object v6, v12

    .line 160
    move-object v2, v14

    .line 161
    move v10, v9

    .line 162
    move-object v9, v13

    .line 163
    :cond_4
    if-eq v10, v8, :cond_5

    .line 164
    .line 165
    add-int/lit8 v10, v10, 0x1

    .line 166
    .line 167
    goto :goto_0

    .line 168
    :cond_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object v0
.end method
