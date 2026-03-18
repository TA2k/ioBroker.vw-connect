.class public final Lwk0/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lwk0/s1;


# direct methods
.method public synthetic constructor <init>(Lwk0/s1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lwk0/i1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwk0/i1;->e:Lwk0/s1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lwk0/h1;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lwk0/h1;

    .line 13
    .line 14
    iget v4, v3, Lwk0/h1;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lwk0/h1;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lwk0/h1;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lwk0/h1;-><init>(Lwk0/i1;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lwk0/h1;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lwk0/h1;->g:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    if-ne v5, v6, :cond_1

    .line 41
    .line 42
    iget-object v0, v3, Lwk0/h1;->d:Lwk0/s1;

    .line 43
    .line 44
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 60
    .line 61
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    const v5, 0xffff

    .line 66
    .line 67
    .line 68
    const/4 v7, 0x0

    .line 69
    iget-object v0, v0, Lwk0/i1;->e:Lwk0/s1;

    .line 70
    .line 71
    if-eqz v2, :cond_4

    .line 72
    .line 73
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Lwk0/n1;

    .line 78
    .line 79
    iget-boolean v1, v1, Lwk0/n1;->j:Z

    .line 80
    .line 81
    if-eqz v1, :cond_3

    .line 82
    .line 83
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    move-object v2, v1

    .line 88
    check-cast v2, Lwk0/n1;

    .line 89
    .line 90
    const/16 v17, 0x0

    .line 91
    .line 92
    const v18, 0xfffb

    .line 93
    .line 94
    .line 95
    const/4 v3, 0x0

    .line 96
    const/4 v4, 0x0

    .line 97
    const/4 v5, 0x1

    .line 98
    const/4 v6, 0x0

    .line 99
    const/4 v7, 0x0

    .line 100
    const/4 v8, 0x0

    .line 101
    const/4 v9, 0x0

    .line 102
    const/4 v10, 0x0

    .line 103
    const/4 v11, 0x0

    .line 104
    const/4 v12, 0x0

    .line 105
    const/4 v13, 0x0

    .line 106
    const/4 v14, 0x0

    .line 107
    const/4 v15, 0x0

    .line 108
    const/16 v16, 0x0

    .line 109
    .line 110
    invoke-static/range {v2 .. v18}, Lwk0/n1;->a(Lwk0/n1;Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lb71/o;ZZZZLwk0/l1;ZI)Lwk0/n1;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    goto :goto_3

    .line 115
    :cond_3
    new-instance v1, Lwk0/n1;

    .line 116
    .line 117
    invoke-direct {v1, v7, v7, v5}, Lwk0/n1;-><init>(Lwk0/m1;Lay0/a;I)V

    .line 118
    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_4
    instance-of v2, v1, Lne0/e;

    .line 122
    .line 123
    if-eqz v2, :cond_6

    .line 124
    .line 125
    check-cast v1, Lne0/e;

    .line 126
    .line 127
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v1, Lvk0/j0;

    .line 130
    .line 131
    iput-object v0, v3, Lwk0/h1;->d:Lwk0/s1;

    .line 132
    .line 133
    iput v6, v3, Lwk0/h1;->g:I

    .line 134
    .line 135
    invoke-static {v0, v1, v3}, Lwk0/s1;->k(Lwk0/s1;Lvk0/j0;Lrx0/c;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    if-ne v2, v4, :cond_5

    .line 140
    .line 141
    return-object v4

    .line 142
    :cond_5
    :goto_1
    move-object v1, v2

    .line 143
    check-cast v1, Lwk0/n1;

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_6
    instance-of v2, v1, Lne0/c;

    .line 147
    .line 148
    if-nez v2, :cond_8

    .line 149
    .line 150
    if-nez v1, :cond_7

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_7
    new-instance v0, La8/r0;

    .line 154
    .line 155
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 156
    .line 157
    .line 158
    throw v0

    .line 159
    :cond_8
    :goto_2
    new-instance v1, Lwk0/n1;

    .line 160
    .line 161
    invoke-direct {v1, v7, v7, v5}, Lwk0/n1;-><init>(Lwk0/m1;Lay0/a;I)V

    .line 162
    .line 163
    .line 164
    :goto_3
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 165
    .line 166
    .line 167
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    return-object v0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lwk0/i1;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lqp0/r;

    .line 13
    .line 14
    iget-object v0, v0, Lwk0/i1;->e:Lwk0/s1;

    .line 15
    .line 16
    invoke-static {v0, v1}, Lwk0/s1;->h(Lwk0/s1;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    if-ne v0, v1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    :goto_0
    return-object v0

    .line 28
    :pswitch_0
    move-object/from16 v1, p1

    .line 29
    .line 30
    check-cast v1, Ljava/lang/Boolean;

    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    iget-object v0, v0, Lwk0/i1;->e:Lwk0/s1;

    .line 36
    .line 37
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    move-object v2, v1

    .line 42
    check-cast v2, Lwk0/n1;

    .line 43
    .line 44
    const/16 v17, 0x0

    .line 45
    .line 46
    const v18, 0xfdff

    .line 47
    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    const/4 v4, 0x0

    .line 51
    const/4 v5, 0x0

    .line 52
    const/4 v6, 0x0

    .line 53
    const/4 v7, 0x0

    .line 54
    const/4 v8, 0x0

    .line 55
    const/4 v9, 0x0

    .line 56
    const/4 v10, 0x0

    .line 57
    const/4 v11, 0x0

    .line 58
    const/4 v12, 0x1

    .line 59
    const/4 v13, 0x0

    .line 60
    const/4 v14, 0x0

    .line 61
    const/4 v15, 0x0

    .line 62
    const/16 v16, 0x0

    .line 63
    .line 64
    invoke-static/range {v2 .. v18}, Lwk0/n1;->a(Lwk0/n1;Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lb71/o;ZZZZLwk0/l1;ZI)Lwk0/n1;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 69
    .line 70
    .line 71
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object v0

    .line 74
    :pswitch_1
    move-object/from16 v2, p1

    .line 75
    .line 76
    check-cast v2, Lne0/s;

    .line 77
    .line 78
    invoke-virtual {v0, v2, v1}, Lwk0/i1;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    return-object v0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
