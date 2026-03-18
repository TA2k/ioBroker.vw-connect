.class public final Lwq0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ltq0/k;

.field public final b:Lwq0/r;


# direct methods
.method public constructor <init>(Ltq0/k;Lwq0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/t0;->a:Ltq0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/t0;->b:Lwq0/r;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lwq0/t0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lwq0/s0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lwq0/s0;

    .line 11
    .line 12
    iget v3, v2, Lwq0/s0;->g:I

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
    iput v3, v2, Lwq0/s0;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lwq0/s0;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lwq0/s0;-><init>(Lwq0/t0;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lwq0/s0;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lwq0/s0;->g:I

    .line 34
    .line 35
    iget-object v5, v0, Lwq0/t0;->b:Lwq0/r;

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    const/4 v11, 0x0

    .line 39
    if-eqz v4, :cond_2

    .line 40
    .line 41
    if-ne v4, v6, :cond_1

    .line 42
    .line 43
    iget-object v0, v2, Lwq0/s0;->d:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

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
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object v1, v5

    .line 61
    check-cast v1, Ltq0/a;

    .line 62
    .line 63
    iget-object v9, v1, Ltq0/a;->b:Ljava/lang/String;

    .line 64
    .line 65
    if-nez v9, :cond_3

    .line 66
    .line 67
    new-instance v12, Lne0/c;

    .line 68
    .line 69
    new-instance v13, Laq/c;

    .line 70
    .line 71
    const-string v0, "Unable to get the SPIN from local repository"

    .line 72
    .line 73
    const/16 v1, 0xa

    .line 74
    .line 75
    invoke-direct {v13, v0, v1}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 76
    .line 77
    .line 78
    const/16 v16, 0x0

    .line 79
    .line 80
    const/16 v17, 0x1e

    .line 81
    .line 82
    const/4 v14, 0x0

    .line 83
    const/4 v15, 0x0

    .line 84
    invoke-direct/range {v12 .. v17}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 85
    .line 86
    .line 87
    return-object v12

    .line 88
    :cond_3
    iget-object v10, v1, Ltq0/a;->c:Ljava/lang/String;

    .line 89
    .line 90
    if-nez v10, :cond_4

    .line 91
    .line 92
    new-instance v12, Lne0/c;

    .line 93
    .line 94
    new-instance v13, Laq/c;

    .line 95
    .line 96
    const-string v0, "Unable to get the new SPIN from local repository"

    .line 97
    .line 98
    const/16 v1, 0xa

    .line 99
    .line 100
    invoke-direct {v13, v0, v1}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 101
    .line 102
    .line 103
    const/16 v16, 0x0

    .line 104
    .line 105
    const/16 v17, 0x1e

    .line 106
    .line 107
    const/4 v14, 0x0

    .line 108
    const/4 v15, 0x0

    .line 109
    invoke-direct/range {v12 .. v17}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 110
    .line 111
    .line 112
    return-object v12

    .line 113
    :cond_4
    iput-object v10, v2, Lwq0/s0;->d:Ljava/lang/String;

    .line 114
    .line 115
    iput v6, v2, Lwq0/s0;->g:I

    .line 116
    .line 117
    iget-object v8, v0, Lwq0/t0;->a:Ltq0/k;

    .line 118
    .line 119
    iget-object v0, v8, Ltq0/k;->a:Lxl0/f;

    .line 120
    .line 121
    new-instance v7, Lo10/l;

    .line 122
    .line 123
    const/16 v12, 0xb

    .line 124
    .line 125
    invoke-direct/range {v7 .. v12}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v0, v7, v2}, Lxl0/f;->i(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    if-ne v1, v3, :cond_5

    .line 133
    .line 134
    return-object v3

    .line 135
    :cond_5
    move-object v0, v10

    .line 136
    :goto_1
    check-cast v1, Lne0/t;

    .line 137
    .line 138
    instance-of v2, v1, Lne0/e;

    .line 139
    .line 140
    if-eqz v2, :cond_6

    .line 141
    .line 142
    move-object v2, v1

    .line 143
    check-cast v2, Lne0/e;

    .line 144
    .line 145
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v2, Llx0/b0;

    .line 148
    .line 149
    check-cast v5, Ltq0/a;

    .line 150
    .line 151
    iput-object v0, v5, Ltq0/a;->b:Ljava/lang/String;

    .line 152
    .line 153
    iput-object v11, v5, Ltq0/a;->c:Ljava/lang/String;

    .line 154
    .line 155
    :cond_6
    return-object v1
.end method
