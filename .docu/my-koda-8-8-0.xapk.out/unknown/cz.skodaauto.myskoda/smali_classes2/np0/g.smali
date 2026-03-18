.class public final Lnp0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpp0/d0;
.implements Lme0/a;


# static fields
.field public static final c:Lqp0/r;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lyy0/m1;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lqp0/r;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    const/4 v7, 0x1

    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x1

    .line 7
    const/4 v3, 0x1

    .line 8
    const/4 v4, 0x1

    .line 9
    const/4 v5, 0x0

    .line 10
    invoke-direct/range {v0 .. v7}, Lqp0/r;-><init>(ZZZZLqr0/l;Lqr0/l;Z)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lnp0/g;->c:Lqp0/r;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Lti0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnp0/g;->a:Lti0/a;

    .line 5
    .line 6
    new-instance p1, Lk31/l;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/16 v1, 0x1d

    .line 10
    .line 11
    invoke-direct {p1, p0, v0, v1}, Lk31/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    new-instance v0, Lyy0/m1;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lnp0/g;->b:Lyy0/m1;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lnp0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lnp0/d;

    .line 7
    .line 8
    iget v1, v0, Lnp0/d;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lnp0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lnp0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lnp0/d;-><init>(Lnp0/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lnp0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lnp0/d;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v5, v0, Lnp0/d;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Lnp0/g;->a:Lti0/a;

    .line 63
    .line 64
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Lnp0/i;

    .line 72
    .line 73
    iput v4, v0, Lnp0/d;->f:I

    .line 74
    .line 75
    iget-object p0, p1, Lnp0/i;->a:Lla/u;

    .line 76
    .line 77
    new-instance p1, Lnh/i;

    .line 78
    .line 79
    const/4 v2, 0x6

    .line 80
    invoke-direct {p1, v2}, Lnh/i;-><init>(I)V

    .line 81
    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-static {v0, p0, v2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v1, :cond_5

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    move-object p0, v3

    .line 92
    :goto_2
    if-ne p0, v1, :cond_6

    .line 93
    .line 94
    :goto_3
    return-object v1

    .line 95
    :cond_6
    return-object v3
.end method

.method public final b(Lqp0/r;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lnp0/f;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lnp0/f;

    .line 11
    .line 12
    iget v3, v2, Lnp0/f;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lnp0/f;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lnp0/f;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lnp0/f;-><init>(Lnp0/g;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lnp0/f;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lnp0/f;->g:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x1

    .line 39
    if-eqz v4, :cond_3

    .line 40
    .line 41
    if-eq v4, v7, :cond_2

    .line 42
    .line 43
    if-ne v4, v6, :cond_1

    .line 44
    .line 45
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v5

    .line 49
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v0

    .line 57
    :cond_2
    iget-object v0, v2, Lnp0/f;->d:Lqp0/r;

    .line 58
    .line 59
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    move-object/from16 v1, p1

    .line 67
    .line 68
    iput-object v1, v2, Lnp0/f;->d:Lqp0/r;

    .line 69
    .line 70
    iput v7, v2, Lnp0/f;->g:I

    .line 71
    .line 72
    iget-object v0, v0, Lnp0/g;->a:Lti0/a;

    .line 73
    .line 74
    invoke-interface {v0, v2}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    if-ne v0, v3, :cond_4

    .line 79
    .line 80
    goto :goto_5

    .line 81
    :cond_4
    move-object/from16 v17, v1

    .line 82
    .line 83
    move-object v1, v0

    .line 84
    move-object/from16 v0, v17

    .line 85
    .line 86
    :goto_1
    check-cast v1, Lnp0/i;

    .line 87
    .line 88
    const-string v4, "<this>"

    .line 89
    .line 90
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    new-instance v8, Lnp0/j;

    .line 94
    .line 95
    iget-boolean v10, v0, Lqp0/r;->a:Z

    .line 96
    .line 97
    iget-boolean v11, v0, Lqp0/r;->b:Z

    .line 98
    .line 99
    iget-boolean v12, v0, Lqp0/r;->c:Z

    .line 100
    .line 101
    iget-boolean v13, v0, Lqp0/r;->d:Z

    .line 102
    .line 103
    iget-object v4, v0, Lqp0/r;->e:Lqr0/l;

    .line 104
    .line 105
    const/4 v9, 0x0

    .line 106
    if-eqz v4, :cond_5

    .line 107
    .line 108
    iget v4, v4, Lqr0/l;->d:I

    .line 109
    .line 110
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    move-object v14, v4

    .line 115
    goto :goto_2

    .line 116
    :cond_5
    move-object v14, v9

    .line 117
    :goto_2
    iget-object v4, v0, Lqp0/r;->f:Lqr0/l;

    .line 118
    .line 119
    if-eqz v4, :cond_6

    .line 120
    .line 121
    iget v4, v4, Lqr0/l;->d:I

    .line 122
    .line 123
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    move-object v15, v4

    .line 128
    goto :goto_3

    .line 129
    :cond_6
    move-object v15, v9

    .line 130
    :goto_3
    iget-boolean v0, v0, Lqp0/r;->g:Z

    .line 131
    .line 132
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 133
    .line 134
    .line 135
    move-result-object v16

    .line 136
    move-object v0, v9

    .line 137
    const/4 v9, 0x1

    .line 138
    invoke-direct/range {v8 .. v16}, Lnp0/j;-><init>(IZZZZLjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Boolean;)V

    .line 139
    .line 140
    .line 141
    iput-object v0, v2, Lnp0/f;->d:Lqp0/r;

    .line 142
    .line 143
    iput v6, v2, Lnp0/f;->g:I

    .line 144
    .line 145
    iget-object v0, v1, Lnp0/i;->a:Lla/u;

    .line 146
    .line 147
    new-instance v4, Ll2/v1;

    .line 148
    .line 149
    const/16 v6, 0x14

    .line 150
    .line 151
    invoke-direct {v4, v6, v1, v8}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    const/4 v1, 0x0

    .line 155
    invoke-static {v2, v0, v1, v7, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    if-ne v0, v3, :cond_7

    .line 160
    .line 161
    goto :goto_4

    .line 162
    :cond_7
    move-object v0, v5

    .line 163
    :goto_4
    if-ne v0, v3, :cond_8

    .line 164
    .line 165
    :goto_5
    return-object v3

    .line 166
    :cond_8
    return-object v5
.end method
