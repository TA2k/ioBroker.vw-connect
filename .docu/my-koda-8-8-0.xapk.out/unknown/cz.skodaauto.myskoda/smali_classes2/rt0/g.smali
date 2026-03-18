.class public final Lrt0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# static fields
.field public static final d:Ljava/lang/Exception;

.field public static final e:Ljava/lang/Exception;

.field public static final f:Ljava/lang/Exception;

.field public static final g:Ljava/lang/Exception;


# instance fields
.field public final a:Lkf0/k;

.field public final b:Lrt0/j;

.field public final c:Lsf0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/Exception;

    .line 2
    .line 3
    const-string v1, "User has insufficient rights!"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lrt0/g;->d:Ljava/lang/Exception;

    .line 9
    .line 10
    new-instance v0, Ljava/lang/Exception;

    .line 11
    .line 12
    const-string v1, "User has insufficient spin!"

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lrt0/g;->e:Ljava/lang/Exception;

    .line 18
    .line 19
    new-instance v0, Ljava/lang/Exception;

    .line 20
    .line 21
    const-string v1, "Missing vehicle status!"

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lrt0/g;->f:Ljava/lang/Exception;

    .line 27
    .line 28
    new-instance v0, Ljava/lang/Exception;

    .line 29
    .line 30
    const-string v1, "Car has doors opened!"

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lrt0/g;->g:Ljava/lang/Exception;

    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(Lkf0/k;Lrt0/j;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrt0/g;->a:Lkf0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lrt0/g;->b:Lrt0/j;

    .line 7
    .line 8
    iput-object p3, p0, Lrt0/g;->c:Lsf0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lrt0/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lrt0/g;->c(Lrt0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lrt0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lrt0/e;

    .line 7
    .line 8
    iget v1, v0, Lrt0/e;->f:I

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
    iput v1, v0, Lrt0/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrt0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lrt0/e;-><init>(Lrt0/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lrt0/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrt0/e;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    new-instance p1, Lrt0/h;

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    invoke-direct {p1, v2}, Lrt0/h;-><init>(Z)V

    .line 56
    .line 57
    .line 58
    iget-object v2, p0, Lrt0/g;->b:Lrt0/j;

    .line 59
    .line 60
    invoke-virtual {v2, p1}, Lrt0/j;->a(Lrt0/h;)Lzy0/j;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    new-instance v2, Lal0/m0;

    .line 65
    .line 66
    const/16 v5, 0x17

    .line 67
    .line 68
    const/4 v6, 0x2

    .line 69
    invoke-direct {v2, v6, v4, v5}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    new-instance v5, Lne0/n;

    .line 73
    .line 74
    invoke-direct {v5, v2, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lrt0/g;->c:Lsf0/a;

    .line 78
    .line 79
    invoke-static {v5, p0, v4}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    new-instance p1, Lam0/i;

    .line 84
    .line 85
    const/16 v2, 0x16

    .line 86
    .line 87
    invoke-direct {p1, p0, v2}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 88
    .line 89
    .line 90
    new-instance p0, Lam0/i;

    .line 91
    .line 92
    const/16 v2, 0x17

    .line 93
    .line 94
    invoke-direct {p0, p1, v2}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 95
    .line 96
    .line 97
    iput v3, v0, Lrt0/e;->f:I

    .line 98
    .line 99
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    if-ne p1, v1, :cond_3

    .line 104
    .line 105
    return-object v1

    .line 106
    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 107
    .line 108
    if-eqz p1, :cond_6

    .line 109
    .line 110
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    new-instance v5, Lne0/c;

    .line 115
    .line 116
    const/4 v9, 0x0

    .line 117
    const/16 v10, 0x1e

    .line 118
    .line 119
    sget-object v6, Lrt0/g;->g:Ljava/lang/Exception;

    .line 120
    .line 121
    const/4 v7, 0x0

    .line 122
    const/4 v8, 0x0

    .line 123
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 124
    .line 125
    .line 126
    if-eqz p0, :cond_4

    .line 127
    .line 128
    move-object v4, v5

    .line 129
    :cond_4
    if-nez v4, :cond_5

    .line 130
    .line 131
    new-instance p0, Lne0/e;

    .line 132
    .line 133
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    return-object p0

    .line 139
    :cond_5
    return-object v4

    .line 140
    :cond_6
    new-instance v0, Lne0/c;

    .line 141
    .line 142
    const/4 v4, 0x0

    .line 143
    const/16 v5, 0x1e

    .line 144
    .line 145
    sget-object v1, Lrt0/g;->f:Ljava/lang/Exception;

    .line 146
    .line 147
    const/4 v2, 0x0

    .line 148
    const/4 v3, 0x0

    .line 149
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 150
    .line 151
    .line 152
    return-object v0
.end method

.method public final c(Lrt0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Lrt0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lrt0/f;

    .line 7
    .line 8
    iget v1, v0, Lrt0/f;->g:I

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
    iput v1, v0, Lrt0/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrt0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lrt0/f;-><init>(Lrt0/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lrt0/f;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrt0/f;->g:I

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
    return-object p2

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
    iget-object p1, v0, Lrt0/f;->d:Lrt0/b;

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
    iput-object p1, v0, Lrt0/f;->d:Lrt0/b;

    .line 61
    .line 62
    iput v4, v0, Lrt0/f;->g:I

    .line 63
    .line 64
    iget-object p2, p0, Lrt0/g;->a:Lkf0/k;

    .line 65
    .line 66
    invoke-virtual {p2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    check-cast p2, Lss0/b;

    .line 74
    .line 75
    sget-object v2, Lss0/e;->d:Lss0/e;

    .line 76
    .line 77
    sget-object v4, Lss0/f;->h:Lss0/f;

    .line 78
    .line 79
    sget-object v5, Lss0/f;->g:Lss0/f;

    .line 80
    .line 81
    filled-new-array {v4, v5}, [Lss0/f;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    invoke-static {v4}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    invoke-static {p2, v2, v4}, Llp/pf;->e(Lss0/b;Lss0/e;Ljava/util/List;)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_5

    .line 94
    .line 95
    new-instance v5, Lne0/c;

    .line 96
    .line 97
    const/4 v9, 0x0

    .line 98
    const/16 v10, 0x1e

    .line 99
    .line 100
    sget-object v6, Lrt0/g;->d:Ljava/lang/Exception;

    .line 101
    .line 102
    const/4 v7, 0x0

    .line 103
    const/4 v8, 0x0

    .line 104
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 105
    .line 106
    .line 107
    return-object v5

    .line 108
    :cond_5
    sget-object v4, Lss0/f;->i:Lss0/f;

    .line 109
    .line 110
    invoke-static {p2, v2, v4}, Llp/pf;->d(Lss0/b;Lss0/e;Lss0/f;)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-eqz v2, :cond_6

    .line 115
    .line 116
    new-instance v4, Lne0/c;

    .line 117
    .line 118
    const/4 v8, 0x0

    .line 119
    const/16 v9, 0x1e

    .line 120
    .line 121
    sget-object v5, Lrt0/g;->e:Ljava/lang/Exception;

    .line 122
    .line 123
    const/4 v6, 0x0

    .line 124
    const/4 v7, 0x0

    .line 125
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 126
    .line 127
    .line 128
    return-object v4

    .line 129
    :cond_6
    iget-object p1, p1, Lrt0/b;->a:Lrt0/a;

    .line 130
    .line 131
    sget-object v2, Lrt0/a;->d:Lrt0/a;

    .line 132
    .line 133
    if-ne p1, v2, :cond_8

    .line 134
    .line 135
    sget-object p1, Lss0/e;->G:Lss0/e;

    .line 136
    .line 137
    invoke-static {p2, p1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 138
    .line 139
    .line 140
    move-result p1

    .line 141
    if-eqz p1, :cond_8

    .line 142
    .line 143
    const/4 p1, 0x0

    .line 144
    iput-object p1, v0, Lrt0/f;->d:Lrt0/b;

    .line 145
    .line 146
    iput v3, v0, Lrt0/f;->g:I

    .line 147
    .line 148
    invoke-virtual {p0, v0}, Lrt0/g;->b(Lrx0/c;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-ne p0, v1, :cond_7

    .line 153
    .line 154
    :goto_2
    return-object v1

    .line 155
    :cond_7
    return-object p0

    .line 156
    :cond_8
    new-instance p0, Lne0/e;

    .line 157
    .line 158
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 159
    .line 160
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    return-object p0
.end method
