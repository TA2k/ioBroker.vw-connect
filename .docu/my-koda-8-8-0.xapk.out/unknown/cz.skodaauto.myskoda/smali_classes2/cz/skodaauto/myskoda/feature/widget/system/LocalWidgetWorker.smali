.class public final Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;
.super Landroidx/work/CoroutineWorker;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly11/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u0002B\u0017\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;",
        "Landroidx/work/CoroutineWorker;",
        "Ly11/a;",
        "Landroid/content/Context;",
        "appContext",
        "Landroidx/work/WorkerParameters;",
        "params",
        "<init>",
        "(Landroid/content/Context;Landroidx/work/WorkerParameters;)V",
        "widget_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final j:Ljava/lang/Object;

.field public final k:Ljava/lang/Object;

.field public final l:Ljava/lang/Object;

.field public final m:Ljava/lang/Object;

.field public final n:Lza0/q;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V
    .locals 1

    .line 1
    const-string v0, "appContext"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "params"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1, p2}, Landroidx/work/CoroutineWorker;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V

    .line 12
    .line 13
    .line 14
    sget-object p1, Llx0/j;->d:Llx0/j;

    .line 15
    .line 16
    new-instance p2, Lbp0/h;

    .line 17
    .line 18
    const/16 v0, 0xf

    .line 19
    .line 20
    invoke-direct {p2, p0, v0}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    iput-object p2, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->j:Ljava/lang/Object;

    .line 28
    .line 29
    new-instance p2, Lbp0/h;

    .line 30
    .line 31
    const/16 v0, 0x10

    .line 32
    .line 33
    invoke-direct {p2, p0, v0}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    iput-object p2, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->k:Ljava/lang/Object;

    .line 41
    .line 42
    const-string p2, "bff-api-auth-no-ssl-pinning"

    .line 43
    .line 44
    invoke-static {p2}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    new-instance v0, Lep0/f;

    .line 49
    .line 50
    invoke-direct {v0, p0, p2}, Lep0/f;-><init>(Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;Lh21/b;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p1, v0}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    iput-object p2, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->l:Ljava/lang/Object;

    .line 58
    .line 59
    new-instance p2, Lbp0/h;

    .line 60
    .line 61
    const/16 v0, 0x11

    .line 62
    .line 63
    invoke-direct {p2, p0, v0}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 64
    .line 65
    .line 66
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->m:Ljava/lang/Object;

    .line 71
    .line 72
    new-instance p1, Lza0/q;

    .line 73
    .line 74
    invoke-direct {p1}, Lza0/q;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object p1, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->n:Lza0/q;

    .line 78
    .line 79
    return-void
.end method

.method public static final f(Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;Ljava/net/URL;)Lmm/g;
    .locals 2

    .line 1
    new-instance v0, Lmm/d;

    .line 2
    .line 3
    iget-object p0, p0, Leb/v;->d:Landroid/content/Context;

    .line 4
    .line 5
    const-string v1, "getApplicationContext(...)"

    .line 6
    .line 7
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0}, Lmm/d;-><init>(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    iput-object p0, v0, Lmm/d;->c:Ljava/lang/Object;

    .line 18
    .line 19
    const/16 p0, 0x280

    .line 20
    .line 21
    invoke-static {p0}, Ljp/sa;->a(I)V

    .line 22
    .line 23
    .line 24
    new-instance p1, Lnm/a;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Lnm/a;-><init>(I)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Lnm/h;

    .line 30
    .line 31
    sget-object v1, Lnm/b;->a:Lnm/b;

    .line 32
    .line 33
    invoke-direct {p0, p1, v1}, Lnm/h;-><init>(Lnm/c;Lnm/c;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Lnm/e;

    .line 37
    .line 38
    invoke-direct {p1, p0}, Lnm/e;-><init>(Lnm/h;)V

    .line 39
    .line 40
    .line 41
    iput-object p1, v0, Lmm/d;->o:Lnm/i;

    .line 42
    .line 43
    invoke-virtual {v0}, Lmm/d;->a()Lmm/g;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method


# virtual methods
.method public final bridge b()Landroidx/lifecycle/c1;
    .locals 0

    .line 1
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lza0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lza0/c;

    .line 7
    .line 8
    iget v1, v0, Lza0/c;->f:I

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
    iput v1, v0, Lza0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lza0/c;

    .line 21
    .line 22
    check-cast p1, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p1}, Lza0/c;-><init>(Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v0, Lza0/c;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lza0/c;->f:I

    .line 32
    .line 33
    const-string v3, "getApplicationContext(...)"

    .line 34
    .line 35
    iget-object v4, p0, Leb/v;->d:Landroid/content/Context;

    .line 36
    .line 37
    iget-object v5, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->n:Lza0/q;

    .line 38
    .line 39
    const/4 v6, 0x4

    .line 40
    const/4 v7, 0x3

    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x1

    .line 43
    if-eqz v2, :cond_5

    .line 44
    .line 45
    if-eq v2, v9, :cond_4

    .line 46
    .line 47
    if-eq v2, v8, :cond_3

    .line 48
    .line 49
    if-eq v2, v7, :cond_2

    .line 50
    .line 51
    if-ne v2, v6, :cond_1

    .line 52
    .line 53
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_6

    .line 57
    .line 58
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_4

    .line 70
    .line 71
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object p1, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->j:Ljava/lang/Object;

    .line 83
    .line 84
    invoke-interface {p1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    check-cast p1, Lwa0/d;

    .line 89
    .line 90
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    check-cast p1, Lyy0/i;

    .line 95
    .line 96
    invoke-static {p1}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    iput v9, v0, Lza0/c;->f:I

    .line 101
    .line 102
    invoke-static {p1, v0}, Lyy0/u;->z(Lyy0/i;Lrx0/c;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    if-ne p1, v1, :cond_6

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_6
    :goto_1
    check-cast p1, Lne0/t;

    .line 110
    .line 111
    instance-of v2, p1, Lne0/c;

    .line 112
    .line 113
    if-eqz v2, :cond_a

    .line 114
    .line 115
    check-cast p1, Lne0/c;

    .line 116
    .line 117
    new-array p0, v8, [Ljava/lang/Exception;

    .line 118
    .line 119
    sget-object v2, Lss0/e0;->d:Lss0/e0;

    .line 120
    .line 121
    const/4 v6, 0x0

    .line 122
    aput-object v2, p0, v6

    .line 123
    .line 124
    sget-object v2, Lss0/h0;->d:Lss0/h0;

    .line 125
    .line 126
    aput-object v2, p0, v9

    .line 127
    .line 128
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    check-cast p0, Ljava/lang/Iterable;

    .line 133
    .line 134
    iget-object p1, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 135
    .line 136
    invoke-static {p0, p1}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    if-nez p0, :cond_8

    .line 141
    .line 142
    const-string p0, "<this>"

    .line 143
    .line 144
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    instance-of p0, p1, Lbm0/d;

    .line 148
    .line 149
    if-eqz p0, :cond_7

    .line 150
    .line 151
    check-cast p1, Lbm0/d;

    .line 152
    .line 153
    iget p0, p1, Lbm0/d;->d:I

    .line 154
    .line 155
    const/16 p1, 0x194

    .line 156
    .line 157
    if-ne p0, p1, :cond_7

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_7
    new-instance p0, Leb/s;

    .line 161
    .line 162
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 163
    .line 164
    .line 165
    return-object p0

    .line 166
    :cond_8
    :goto_2
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    iput v8, v0, Lza0/c;->f:I

    .line 170
    .line 171
    invoke-static {v5, v4, v0}, Lhy0/l0;->h(La7/m0;Landroid/content/Context;Lrx0/c;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    if-ne p0, v1, :cond_9

    .line 176
    .line 177
    goto :goto_5

    .line 178
    :cond_9
    :goto_3
    new-instance p0, Leb/r;

    .line 179
    .line 180
    invoke-direct {p0}, Leb/r;-><init>()V

    .line 181
    .line 182
    .line 183
    return-object p0

    .line 184
    :cond_a
    instance-of v2, p1, Lne0/e;

    .line 185
    .line 186
    if-eqz v2, :cond_d

    .line 187
    .line 188
    check-cast p1, Lne0/e;

    .line 189
    .line 190
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast p1, Lxa0/a;

    .line 193
    .line 194
    iput v7, v0, Lza0/c;->f:I

    .line 195
    .line 196
    invoke-virtual {p0, p1, v0}, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->g(Lxa0/a;Lrx0/c;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    if-ne p0, v1, :cond_b

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_b
    :goto_4
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    iput v6, v0, Lza0/c;->f:I

    .line 207
    .line 208
    invoke-static {v5, v4, v0}, Lhy0/l0;->h(La7/m0;Landroid/content/Context;Lrx0/c;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    if-ne p0, v1, :cond_c

    .line 213
    .line 214
    :goto_5
    return-object v1

    .line 215
    :cond_c
    :goto_6
    new-instance p0, Leb/t;

    .line 216
    .line 217
    sget-object p1, Leb/h;->b:Leb/h;

    .line 218
    .line 219
    invoke-direct {p0, p1}, Leb/t;-><init>(Leb/h;)V

    .line 220
    .line 221
    .line 222
    return-object p0

    .line 223
    :cond_d
    new-instance p0, La8/r0;

    .line 224
    .line 225
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 226
    .line 227
    .line 228
    throw p0
.end method

.method public final g(Lxa0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lza0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lza0/a;

    .line 7
    .line 8
    iget v1, v0, Lza0/a;->g:I

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
    iput v1, v0, Lza0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lza0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lza0/a;-><init>(Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lza0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lza0/a;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_3

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
    iget-object p1, v0, Lza0/a;->d:Lxa0/a;

    .line 53
    .line 54
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    new-instance p2, Lqh/a;

    .line 62
    .line 63
    const/16 v2, 0x16

    .line 64
    .line 65
    invoke-direct {p2, v2, p1, p0, v3}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 66
    .line 67
    .line 68
    iput-object p1, v0, Lza0/a;->d:Lxa0/a;

    .line 69
    .line 70
    iput v5, v0, Lza0/a;->g:I

    .line 71
    .line 72
    invoke-static {p2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    :goto_1
    iget-object p0, p0, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;->k:Ljava/lang/Object;

    .line 80
    .line 81
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lwa0/g;

    .line 86
    .line 87
    iput-object v3, v0, Lza0/a;->d:Lxa0/a;

    .line 88
    .line 89
    iput v4, v0, Lza0/a;->g:I

    .line 90
    .line 91
    invoke-virtual {p0, p1, v0}, Lwa0/g;->b(Lxa0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    if-ne p0, v1, :cond_5

    .line 96
    .line 97
    :goto_2
    return-object v1

    .line 98
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0
.end method
