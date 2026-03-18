.class public final Lo10/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lq10/f;
.implements Lme0/a;
.implements Lme0/b;


# static fields
.field public static final k:Lne0/c;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lti0/a;

.field public final c:Lti0/a;

.field public final d:Lwe0/a;

.field public final e:Lny/d;

.field public final f:Lez0/c;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;

.field public final i:Lyy0/c2;

.field public final j:Lyy0/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lne0/c;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/Exception;

    .line 4
    .line 5
    const-string v2, "No data"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    const/16 v5, 0x1e

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lo10/t;->k:Lne0/c;

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(Lti0/a;Lti0/a;Lti0/a;Lwe0/a;Lny/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo10/t;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lo10/t;->b:Lti0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lo10/t;->c:Lti0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lo10/t;->d:Lwe0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lo10/t;->e:Lny/d;

    .line 13
    .line 14
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lo10/t;->f:Lez0/c;

    .line 19
    .line 20
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 21
    .line 22
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lo10/t;->g:Lyy0/c2;

    .line 27
    .line 28
    new-instance p2, Lyy0/l1;

    .line 29
    .line 30
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 31
    .line 32
    .line 33
    iput-object p2, p0, Lo10/t;->h:Lyy0/l1;

    .line 34
    .line 35
    const/4 p1, 0x0

    .line 36
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Lo10/t;->i:Lyy0/c2;

    .line 41
    .line 42
    new-instance p2, Lyy0/l1;

    .line 43
    .line 44
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 45
    .line 46
    .line 47
    iput-object p2, p0, Lo10/t;->j:Lyy0/l1;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lo10/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lo10/n;

    .line 7
    .line 8
    iget v1, v0, Lo10/n;->f:I

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
    iput v1, v0, Lo10/n;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo10/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lo10/n;-><init>(Lo10/t;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lo10/n;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo10/n;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    const/4 v5, 0x1

    .line 35
    packed-switch v2, :pswitch_data_0

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto/16 :goto_a

    .line 50
    .line 51
    :pswitch_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto/16 :goto_7

    .line 55
    .line 56
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_6

    .line 60
    :pswitch_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_4

    .line 64
    :pswitch_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_3

    .line 68
    :pswitch_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object p1, p0, Lo10/t;->i:Lyy0/c2;

    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    invoke-virtual {p1, v2}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iput v5, v0, Lo10/n;->f:I

    .line 82
    .line 83
    iget-object p1, p0, Lo10/t;->a:Lti0/a;

    .line 84
    .line 85
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-ne p1, v1, :cond_1

    .line 90
    .line 91
    goto/16 :goto_9

    .line 92
    .line 93
    :cond_1
    :goto_1
    check-cast p1, Lo10/e;

    .line 94
    .line 95
    const/4 v2, 0x2

    .line 96
    iput v2, v0, Lo10/n;->f:I

    .line 97
    .line 98
    iget-object p1, p1, Lo10/e;->a:Lla/u;

    .line 99
    .line 100
    new-instance v2, Lnh/i;

    .line 101
    .line 102
    const/16 v6, 0x13

    .line 103
    .line 104
    invoke-direct {v2, v6}, Lnh/i;-><init>(I)V

    .line 105
    .line 106
    .line 107
    invoke-static {v0, p1, v3, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    if-ne p1, v1, :cond_2

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_2
    move-object p1, v4

    .line 115
    :goto_2
    if-ne p1, v1, :cond_3

    .line 116
    .line 117
    goto :goto_9

    .line 118
    :cond_3
    :goto_3
    const/4 p1, 0x3

    .line 119
    iput p1, v0, Lo10/n;->f:I

    .line 120
    .line 121
    iget-object p1, p0, Lo10/t;->b:Lti0/a;

    .line 122
    .line 123
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    if-ne p1, v1, :cond_4

    .line 128
    .line 129
    goto :goto_9

    .line 130
    :cond_4
    :goto_4
    check-cast p1, Lo10/h;

    .line 131
    .line 132
    const/4 v2, 0x4

    .line 133
    iput v2, v0, Lo10/n;->f:I

    .line 134
    .line 135
    iget-object p1, p1, Lo10/h;->a:Lla/u;

    .line 136
    .line 137
    new-instance v2, Lnh/i;

    .line 138
    .line 139
    const/16 v6, 0x14

    .line 140
    .line 141
    invoke-direct {v2, v6}, Lnh/i;-><init>(I)V

    .line 142
    .line 143
    .line 144
    invoke-static {v0, p1, v3, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    if-ne p1, v1, :cond_5

    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_5
    move-object p1, v4

    .line 152
    :goto_5
    if-ne p1, v1, :cond_6

    .line 153
    .line 154
    goto :goto_9

    .line 155
    :cond_6
    :goto_6
    const/4 p1, 0x5

    .line 156
    iput p1, v0, Lo10/n;->f:I

    .line 157
    .line 158
    iget-object p1, p0, Lo10/t;->c:Lti0/a;

    .line 159
    .line 160
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    if-ne p1, v1, :cond_7

    .line 165
    .line 166
    goto :goto_9

    .line 167
    :cond_7
    :goto_7
    check-cast p1, Lo10/a;

    .line 168
    .line 169
    const/4 v2, 0x6

    .line 170
    iput v2, v0, Lo10/n;->f:I

    .line 171
    .line 172
    iget-object p1, p1, Lo10/a;->a:Lla/u;

    .line 173
    .line 174
    new-instance v2, Lnh/i;

    .line 175
    .line 176
    const/16 v6, 0x12

    .line 177
    .line 178
    invoke-direct {v2, v6}, Lnh/i;-><init>(I)V

    .line 179
    .line 180
    .line 181
    invoke-static {v0, p1, v3, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    if-ne p1, v1, :cond_8

    .line 186
    .line 187
    goto :goto_8

    .line 188
    :cond_8
    move-object p1, v4

    .line 189
    :goto_8
    if-ne p1, v1, :cond_9

    .line 190
    .line 191
    :goto_9
    return-object v1

    .line 192
    :cond_9
    :goto_a
    iget-object p0, p0, Lo10/t;->d:Lwe0/a;

    .line 193
    .line 194
    check-cast p0, Lwe0/c;

    .line 195
    .line 196
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 197
    .line 198
    .line 199
    return-object v4

    .line 200
    nop

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lo10/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lo10/o;

    .line 7
    .line 8
    iget v1, v0, Lo10/o;->g:I

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
    iput v1, v0, Lo10/o;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo10/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lo10/o;-><init>(Lo10/t;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lo10/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo10/o;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-object p1, v0, Lo10/o;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p1, v0, Lo10/o;->d:Ljava/lang/String;

    .line 61
    .line 62
    iput v4, v0, Lo10/o;->g:I

    .line 63
    .line 64
    iget-object p0, p0, Lo10/t;->a:Lti0/a;

    .line 65
    .line 66
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    if-ne p2, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p2, Lo10/e;

    .line 74
    .line 75
    const/4 p0, 0x0

    .line 76
    iput-object p0, v0, Lo10/o;->d:Ljava/lang/String;

    .line 77
    .line 78
    iput v3, v0, Lo10/o;->g:I

    .line 79
    .line 80
    iget-object p0, p2, Lo10/e;->a:Lla/u;

    .line 81
    .line 82
    new-instance v2, Lo10/c;

    .line 83
    .line 84
    const/4 v3, 0x1

    .line 85
    invoke-direct {v2, p1, p2, v3}, Lo10/c;-><init>(Ljava/lang/String;Lo10/e;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {v0, p0, v4, v4, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    if-ne p2, v1, :cond_5

    .line 93
    .line 94
    :goto_2
    return-object v1

    .line 95
    :cond_5
    :goto_3
    if-eqz p2, :cond_6

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    const/4 v4, 0x0

    .line 99
    :goto_4
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lo10/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lo10/p;

    .line 7
    .line 8
    iget v1, v0, Lo10/p;->g:I

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
    iput v1, v0, Lo10/p;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo10/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lo10/p;-><init>(Lo10/t;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lo10/p;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo10/p;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lo10/p;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lo10/p;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lo10/p;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lo10/t;->a:Lti0/a;

    .line 58
    .line 59
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-ne p2, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p2, Lo10/e;

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    const-string p0, "vin"

    .line 72
    .line 73
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object p0, p2, Lo10/e;->a:Lla/u;

    .line 77
    .line 78
    const-string v0, "departure_timer"

    .line 79
    .line 80
    const-string v1, "departure_plan"

    .line 81
    .line 82
    const-string v2, "departure_charging_time"

    .line 83
    .line 84
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    new-instance v1, Lo10/c;

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    invoke-direct {v1, p1, p2, v2}, Lo10/c;-><init>(Ljava/lang/String;Lo10/e;I)V

    .line 92
    .line 93
    .line 94
    invoke-static {p0, v3, v0, v1}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    new-instance p1, Lic0/i;

    .line 99
    .line 100
    const/4 p2, 0x3

    .line 101
    invoke-direct {p1, p0, p2}, Lic0/i;-><init>(Lna/j;I)V

    .line 102
    .line 103
    .line 104
    return-object p1
.end method

.method public final d(Ljava/lang/String;Lne0/s;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lo10/r;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lo10/r;

    .line 7
    .line 8
    iget v1, v0, Lo10/r;->f:I

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
    iput v1, v0, Lo10/r;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo10/r;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lo10/r;-><init>(Lo10/t;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lo10/r;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo10/r;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Lo10/t;->d:Lwe0/a;

    .line 32
    .line 33
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    if-ne v2, v5, :cond_1

    .line 39
    .line 40
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    instance-of p3, p2, Lne0/e;

    .line 56
    .line 57
    if-eqz p3, :cond_5

    .line 58
    .line 59
    check-cast p2, Lne0/e;

    .line 60
    .line 61
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p2, Lr10/a;

    .line 64
    .line 65
    iput v5, v0, Lo10/r;->f:I

    .line 66
    .line 67
    new-instance p3, Lo10/s;

    .line 68
    .line 69
    const/4 v2, 0x0

    .line 70
    invoke-direct {p3, p0, p2, p1, v2}, Lo10/s;-><init>(Lo10/t;Lr10/a;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lo10/t;->e:Lny/d;

    .line 74
    .line 75
    invoke-virtual {p0, p3, v0}, Lny/d;->a(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    move-object p0, v4

    .line 83
    :goto_1
    if-ne p0, v1, :cond_4

    .line 84
    .line 85
    return-object v1

    .line 86
    :cond_4
    :goto_2
    check-cast v3, Lwe0/c;

    .line 87
    .line 88
    invoke-virtual {v3}, Lwe0/c;->c()V

    .line 89
    .line 90
    .line 91
    return-object v4

    .line 92
    :cond_5
    instance-of p0, p2, Lne0/c;

    .line 93
    .line 94
    if-eqz p0, :cond_6

    .line 95
    .line 96
    check-cast v3, Lwe0/c;

    .line 97
    .line 98
    invoke-virtual {v3}, Lwe0/c;->a()V

    .line 99
    .line 100
    .line 101
    return-object v4

    .line 102
    :cond_6
    sget-object p0, Lne0/d;->a:Lne0/d;

    .line 103
    .line 104
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    if-eqz p0, :cond_7

    .line 109
    .line 110
    return-object v4

    .line 111
    :cond_7
    new-instance p0, La8/r0;

    .line 112
    .line 113
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 114
    .line 115
    .line 116
    throw p0
.end method
