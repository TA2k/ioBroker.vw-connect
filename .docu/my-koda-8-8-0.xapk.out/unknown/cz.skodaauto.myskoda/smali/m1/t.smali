.class public final Lm1/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/q2;


# static fields
.field public static final x:Lu2/l;


# instance fields
.field public final a:Lm1/a;

.field public b:Z

.field public c:Lm1/l;

.field public d:Z

.field public final e:Lm1/o;

.field public final f:Ll2/j1;

.field public final g:Li1/l;

.field public h:F

.field public final i:Lg1/f0;

.field public final j:Z

.field public k:Lv3/h0;

.field public final l:Lm1/r;

.field public final m:Lo1/d;

.field public final n:Landroidx/compose/foundation/lazy/layout/b;

.field public final o:Lg1/r;

.field public final p:Lo1/l0;

.field public final q:Lh6/e;

.field public final r:Lo1/i0;

.field public final s:Ll2/b1;

.field public final t:Ll2/j1;

.field public final u:Ll2/j1;

.field public final v:Ll2/b1;

.field public final w:Lb81/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ll20/f;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ll20/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lkq0/a;

    .line 9
    .line 10
    const/16 v2, 0x1a

    .line 11
    .line 12
    invoke-direct {v1, v2}, Lkq0/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Lu2/m;->b(Lay0/n;Lay0/k;)Lu2/l;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lm1/t;->x:Lu2/l;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>(II)V
    .locals 2

    .line 1
    new-instance v0, Lm1/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, -0x1

    .line 7
    iput v1, v0, Lm1/a;->a:I

    .line 8
    .line 9
    iput v1, v0, Lm1/a;->c:I

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lm1/t;->a:Lm1/a;

    .line 15
    .line 16
    new-instance v0, Lm1/o;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-direct {v0, p1, p2, v1}, Lm1/o;-><init>(III)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lm1/t;->e:Lm1/o;

    .line 23
    .line 24
    sget-object p2, Lm1/v;->a:Lm1/l;

    .line 25
    .line 26
    sget-object v0, Ll2/x0;->f:Ll2/x0;

    .line 27
    .line 28
    new-instance v1, Ll2/j1;

    .line 29
    .line 30
    invoke-direct {v1, p2, v0}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lm1/t;->f:Ll2/j1;

    .line 34
    .line 35
    new-instance p2, Li1/l;

    .line 36
    .line 37
    invoke-direct {p2}, Li1/l;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object p2, p0, Lm1/t;->g:Li1/l;

    .line 41
    .line 42
    new-instance p2, Lla/p;

    .line 43
    .line 44
    const/4 v0, 0x3

    .line 45
    invoke-direct {p2, p0, v0}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    new-instance v0, Lg1/f0;

    .line 49
    .line 50
    invoke-direct {v0, p2}, Lg1/f0;-><init>(Lay0/k;)V

    .line 51
    .line 52
    .line 53
    iput-object v0, p0, Lm1/t;->i:Lg1/f0;

    .line 54
    .line 55
    const/4 p2, 0x1

    .line 56
    iput-boolean p2, p0, Lm1/t;->j:Z

    .line 57
    .line 58
    new-instance p2, Lm1/r;

    .line 59
    .line 60
    const/4 v0, 0x0

    .line 61
    invoke-direct {p2, p0, v0}, Lm1/r;-><init>(Lg1/q2;I)V

    .line 62
    .line 63
    .line 64
    iput-object p2, p0, Lm1/t;->l:Lm1/r;

    .line 65
    .line 66
    new-instance p2, Lo1/d;

    .line 67
    .line 68
    invoke-direct {p2}, Lo1/d;-><init>()V

    .line 69
    .line 70
    .line 71
    iput-object p2, p0, Lm1/t;->m:Lo1/d;

    .line 72
    .line 73
    new-instance p2, Landroidx/compose/foundation/lazy/layout/b;

    .line 74
    .line 75
    invoke-direct {p2}, Landroidx/compose/foundation/lazy/layout/b;-><init>()V

    .line 76
    .line 77
    .line 78
    iput-object p2, p0, Lm1/t;->n:Landroidx/compose/foundation/lazy/layout/b;

    .line 79
    .line 80
    new-instance p2, Lg1/r;

    .line 81
    .line 82
    const/4 v0, 0x1

    .line 83
    invoke-direct {p2, v0}, Lg1/r;-><init>(I)V

    .line 84
    .line 85
    .line 86
    iput-object p2, p0, Lm1/t;->o:Lg1/r;

    .line 87
    .line 88
    new-instance p2, Lo1/l0;

    .line 89
    .line 90
    new-instance v0, Lac/g;

    .line 91
    .line 92
    invoke-direct {v0, p0, p1}, Lac/g;-><init>(Lm1/t;I)V

    .line 93
    .line 94
    .line 95
    invoke-direct {p2, v0}, Lo1/l0;-><init>(Lay0/k;)V

    .line 96
    .line 97
    .line 98
    iput-object p2, p0, Lm1/t;->p:Lo1/l0;

    .line 99
    .line 100
    new-instance p1, Lh6/e;

    .line 101
    .line 102
    const/16 p2, 0x15

    .line 103
    .line 104
    invoke-direct {p1, p0, p2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 105
    .line 106
    .line 107
    iput-object p1, p0, Lm1/t;->q:Lh6/e;

    .line 108
    .line 109
    new-instance p1, Lo1/i0;

    .line 110
    .line 111
    invoke-direct {p1}, Lo1/i0;-><init>()V

    .line 112
    .line 113
    .line 114
    iput-object p1, p0, Lm1/t;->r:Lo1/i0;

    .line 115
    .line 116
    invoke-static {}, Lo1/y;->h()Ll2/b1;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    iput-object p1, p0, Lm1/t;->s:Ll2/b1;

    .line 121
    .line 122
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 123
    .line 124
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    iput-object p2, p0, Lm1/t;->t:Ll2/j1;

    .line 129
    .line 130
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    iput-object p1, p0, Lm1/t;->u:Ll2/j1;

    .line 135
    .line 136
    invoke-static {}, Lo1/y;->h()Ll2/b1;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    iput-object p1, p0, Lm1/t;->v:Ll2/b1;

    .line 141
    .line 142
    new-instance p1, Lb81/a;

    .line 143
    .line 144
    const/16 p2, 0x14

    .line 145
    .line 146
    invoke-direct {p1, p2}, Lb81/a;-><init>(I)V

    .line 147
    .line 148
    .line 149
    iput-object p1, p0, Lm1/t;->w:Lb81/a;

    .line 150
    .line 151
    return-void
.end method

.method public static f(Lm1/t;ILrx0/i;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lm1/q;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v0, p1, v2, v1, p0}, Lm1/q;-><init>(IILkotlin/coroutines/Continuation;Lm1/t;)V

    .line 9
    .line 10
    .line 11
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 12
    .line 13
    invoke-virtual {p0, p1, v0, p2}, Lm1/t;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method public static j(Lm1/t;ILrx0/i;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lh2/x2;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lh2/x2;-><init>(Lm1/t;ILkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 11
    .line 12
    invoke-virtual {p0, p1, v0, p2}, Lm1/t;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/t;->i:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lg1/f0;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/t;->u:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lm1/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lm1/s;

    .line 7
    .line 8
    iget v1, v0, Lm1/s;->h:I

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
    iput v1, v0, Lm1/s;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm1/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lm1/s;-><init>(Lm1/t;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lm1/s;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm1/s;->h:I

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

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
    iget-object p1, v0, Lm1/s;->e:Lrx0/i;

    .line 52
    .line 53
    move-object p2, p1

    .line 54
    check-cast p2, Lay0/n;

    .line 55
    .line 56
    iget-object p1, v0, Lm1/s;->d:Le1/w0;

    .line 57
    .line 58
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iput-object p1, v0, Lm1/s;->d:Le1/w0;

    .line 66
    .line 67
    move-object p3, p2

    .line 68
    check-cast p3, Lrx0/i;

    .line 69
    .line 70
    iput-object p3, v0, Lm1/s;->e:Lrx0/i;

    .line 71
    .line 72
    iput v4, v0, Lm1/s;->h:I

    .line 73
    .line 74
    iget-object p3, p0, Lm1/t;->m:Lo1/d;

    .line 75
    .line 76
    invoke-virtual {p3, v0}, Lo1/d;->h(Lrx0/c;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p3

    .line 80
    if-ne p3, v1, :cond_4

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    :goto_1
    const/4 p3, 0x0

    .line 84
    iput-object p3, v0, Lm1/s;->d:Le1/w0;

    .line 85
    .line 86
    iput-object p3, v0, Lm1/s;->e:Lrx0/i;

    .line 87
    .line 88
    iput v3, v0, Lm1/s;->h:I

    .line 89
    .line 90
    iget-object p0, p0, Lm1/t;->i:Lg1/f0;

    .line 91
    .line 92
    invoke-virtual {p0, p1, p2, v0}, Lg1/f0;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v1, :cond_5

    .line 97
    .line 98
    :goto_2
    return-object v1

    .line 99
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/t;->t:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/t;->i:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lg1/f0;->e(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final g(Lm1/l;ZZ)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lm1/l;->k:Ljava/lang/Object;

    .line 6
    .line 7
    iget v3, v1, Lm1/l;->n:I

    .line 8
    .line 9
    iget v4, v1, Lm1/l;->b:I

    .line 10
    .line 11
    iget-object v5, v1, Lm1/l;->a:Lm1/m;

    .line 12
    .line 13
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result v6

    .line 17
    iget-object v7, v0, Lm1/t;->p:Lo1/l0;

    .line 18
    .line 19
    iput v6, v7, Lo1/l0;->e:I

    .line 20
    .line 21
    iget-object v6, v0, Lm1/t;->w:Lb81/a;

    .line 22
    .line 23
    iget-object v7, v0, Lm1/t;->e:Lm1/o;

    .line 24
    .line 25
    const/4 v8, 0x0

    .line 26
    const/4 v9, 0x0

    .line 27
    if-nez p2, :cond_4

    .line 28
    .line 29
    iget-boolean v10, v0, Lm1/t;->b:Z

    .line 30
    .line 31
    if-eqz v10, :cond_4

    .line 32
    .line 33
    iput-object v1, v0, Lm1/t;->c:Lm1/l;

    .line 34
    .line 35
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    if-eqz v1, :cond_0

    .line 40
    .line 41
    invoke-virtual {v1}, Lv2/f;->e()Lay0/k;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    move-object v2, v0

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move-object v2, v8

    .line 48
    :goto_0
    invoke-static {v1}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    :try_start_0
    iget-object v0, v6, Lb81/a;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lc1/k;

    .line 55
    .line 56
    iget-object v0, v0, Lc1/k;->e:Ll2/j1;

    .line 57
    .line 58
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    check-cast v0, Ljava/lang/Number;

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    cmpg-float v0, v0, v9

    .line 69
    .line 70
    if-nez v0, :cond_1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    if-eqz v5, :cond_3

    .line 74
    .line 75
    iget v0, v5, Lm1/m;->a:I

    .line 76
    .line 77
    iget-object v5, v7, Lm1/o;->b:Ll2/g1;

    .line 78
    .line 79
    invoke-virtual {v5}, Ll2/g1;->o()I

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-ne v0, v5, :cond_3

    .line 84
    .line 85
    iget-object v0, v7, Lm1/o;->c:Ll2/g1;

    .line 86
    .line 87
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-ne v4, v0, :cond_3

    .line 92
    .line 93
    iget-object v0, v6, Lb81/a;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lvy0/x1;

    .line 96
    .line 97
    if-eqz v0, :cond_2

    .line 98
    .line 99
    invoke-virtual {v0, v8}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 100
    .line 101
    .line 102
    :cond_2
    new-instance v0, Lc1/k;

    .line 103
    .line 104
    sget-object v4, Lc1/d;->j:Lc1/b2;

    .line 105
    .line 106
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    const/16 v7, 0x3c

    .line 111
    .line 112
    invoke-direct {v0, v4, v5, v8, v7}, Lc1/k;-><init>(Lc1/b2;Ljava/lang/Object;Lc1/p;I)V

    .line 113
    .line 114
    .line 115
    iput-object v0, v6, Lb81/a;->f:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :catchall_0
    move-exception v0

    .line 119
    goto :goto_2

    .line 120
    :cond_3
    :goto_1
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 121
    .line 122
    .line 123
    return-void

    .line 124
    :goto_2
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 125
    .line 126
    .line 127
    throw v0

    .line 128
    :cond_4
    const/4 v10, 0x1

    .line 129
    if-eqz p2, :cond_5

    .line 130
    .line 131
    iput-boolean v10, v0, Lm1/t;->b:Z

    .line 132
    .line 133
    :cond_5
    if-eqz v5, :cond_6

    .line 134
    .line 135
    iget v12, v5, Lm1/m;->a:I

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_6
    const/4 v12, 0x0

    .line 139
    :goto_3
    if-nez v12, :cond_8

    .line 140
    .line 141
    if-eqz v4, :cond_7

    .line 142
    .line 143
    goto :goto_4

    .line 144
    :cond_7
    const/4 v12, 0x0

    .line 145
    goto :goto_5

    .line 146
    :cond_8
    :goto_4
    move v12, v10

    .line 147
    :goto_5
    iget-object v13, v0, Lm1/t;->u:Ll2/j1;

    .line 148
    .line 149
    invoke-static {v12}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 150
    .line 151
    .line 152
    move-result-object v12

    .line 153
    invoke-virtual {v13, v12}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    iget-boolean v12, v1, Lm1/l;->c:Z

    .line 157
    .line 158
    iget-object v13, v0, Lm1/t;->t:Ll2/j1;

    .line 159
    .line 160
    invoke-static {v12}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 161
    .line 162
    .line 163
    move-result-object v12

    .line 164
    invoke-virtual {v13, v12}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    iget v12, v0, Lm1/t;->h:F

    .line 168
    .line 169
    iget v13, v1, Lm1/l;->d:F

    .line 170
    .line 171
    sub-float/2addr v12, v13

    .line 172
    iput v12, v0, Lm1/t;->h:F

    .line 173
    .line 174
    iget-object v12, v0, Lm1/t;->f:Ll2/j1;

    .line 175
    .line 176
    invoke-virtual {v12, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    const-string v12, "scrollOffset should be non-negative"

    .line 180
    .line 181
    if-eqz p3, :cond_b

    .line 182
    .line 183
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    int-to-float v0, v4

    .line 187
    cmpl-float v0, v0, v9

    .line 188
    .line 189
    if-ltz v0, :cond_9

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_9
    const/4 v10, 0x0

    .line 193
    :goto_6
    if-nez v10, :cond_a

    .line 194
    .line 195
    invoke-static {v12}, Lj1/b;->c(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    :cond_a
    iget-object v0, v7, Lm1/o;->c:Ll2/g1;

    .line 199
    .line 200
    invoke-virtual {v0, v4}, Ll2/g1;->p(I)V

    .line 201
    .line 202
    .line 203
    goto/16 :goto_e

    .line 204
    .line 205
    :cond_b
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v13

    .line 209
    check-cast v13, Lm1/m;

    .line 210
    .line 211
    invoke-static {v2}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v14

    .line 215
    check-cast v14, Lm1/m;

    .line 216
    .line 217
    const-wide/16 v15, -0x1

    .line 218
    .line 219
    if-eqz v13, :cond_c

    .line 220
    .line 221
    iget v13, v13, Lm1/m;->a:I

    .line 222
    .line 223
    move-object/from16 v17, v12

    .line 224
    .line 225
    int-to-long v11, v13

    .line 226
    goto :goto_7

    .line 227
    :cond_c
    move-object/from16 v17, v12

    .line 228
    .line 229
    move-wide v11, v15

    .line 230
    :goto_7
    const-string v13, "firstVisibleItem:index"

    .line 231
    .line 232
    invoke-static {v13, v11, v12}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 233
    .line 234
    .line 235
    if-eqz v14, :cond_d

    .line 236
    .line 237
    iget v11, v14, Lm1/m;->a:I

    .line 238
    .line 239
    int-to-long v11, v11

    .line 240
    goto :goto_8

    .line 241
    :cond_d
    move-wide v11, v15

    .line 242
    :goto_8
    const-string v13, "lastVisibleItem:index"

    .line 243
    .line 244
    invoke-static {v13, v11, v12}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 248
    .line 249
    .line 250
    if-eqz v5, :cond_e

    .line 251
    .line 252
    iget-object v11, v5, Lm1/m;->k:Ljava/lang/Object;

    .line 253
    .line 254
    goto :goto_9

    .line 255
    :cond_e
    move-object v11, v8

    .line 256
    :goto_9
    iput-object v11, v7, Lm1/o;->e:Ljava/lang/Object;

    .line 257
    .line 258
    iget-boolean v11, v7, Lm1/o;->d:Z

    .line 259
    .line 260
    if-nez v11, :cond_f

    .line 261
    .line 262
    if-lez v3, :cond_13

    .line 263
    .line 264
    :cond_f
    iput-boolean v10, v7, Lm1/o;->d:Z

    .line 265
    .line 266
    int-to-float v11, v4

    .line 267
    cmpl-float v11, v11, v9

    .line 268
    .line 269
    if-ltz v11, :cond_10

    .line 270
    .line 271
    move v11, v10

    .line 272
    goto :goto_a

    .line 273
    :cond_10
    const/4 v11, 0x0

    .line 274
    :goto_a
    if-nez v11, :cond_11

    .line 275
    .line 276
    invoke-static/range {v17 .. v17}, Lj1/b;->c(Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    :cond_11
    if-eqz v5, :cond_12

    .line 280
    .line 281
    iget v5, v5, Lm1/m;->a:I

    .line 282
    .line 283
    goto :goto_b

    .line 284
    :cond_12
    const/4 v5, 0x0

    .line 285
    :goto_b
    invoke-virtual {v7, v5, v4}, Lm1/o;->a(II)V

    .line 286
    .line 287
    .line 288
    :cond_13
    iget-boolean v4, v0, Lm1/t;->j:Z

    .line 289
    .line 290
    if-eqz v4, :cond_19

    .line 291
    .line 292
    iget-object v4, v0, Lm1/t;->a:Lm1/a;

    .line 293
    .line 294
    iget v5, v4, Lm1/a;->a:I

    .line 295
    .line 296
    iget-boolean v7, v4, Lm1/a;->b:Z

    .line 297
    .line 298
    const/4 v11, -0x1

    .line 299
    if-eq v5, v11, :cond_15

    .line 300
    .line 301
    move-object v12, v2

    .line 302
    check-cast v12, Ljava/util/Collection;

    .line 303
    .line 304
    invoke-interface {v12}, Ljava/util/Collection;->isEmpty()Z

    .line 305
    .line 306
    .line 307
    move-result v12

    .line 308
    if-nez v12, :cond_15

    .line 309
    .line 310
    invoke-static {v1, v7}, Lm1/a;->b(Lm1/l;Z)I

    .line 311
    .line 312
    .line 313
    move-result v7

    .line 314
    if-eq v5, v7, :cond_15

    .line 315
    .line 316
    iput v11, v4, Lm1/a;->a:I

    .line 317
    .line 318
    iget-object v5, v4, Lm1/a;->e:Ljava/lang/Object;

    .line 319
    .line 320
    check-cast v5, Lo1/k0;

    .line 321
    .line 322
    if-eqz v5, :cond_14

    .line 323
    .line 324
    invoke-interface {v5}, Lo1/k0;->cancel()V

    .line 325
    .line 326
    .line 327
    :cond_14
    iput-object v8, v4, Lm1/a;->e:Ljava/lang/Object;

    .line 328
    .line 329
    :cond_15
    iget v5, v4, Lm1/a;->c:I

    .line 330
    .line 331
    if-eq v5, v11, :cond_18

    .line 332
    .line 333
    iget v7, v4, Lm1/a;->d:F

    .line 334
    .line 335
    cmpg-float v7, v7, v9

    .line 336
    .line 337
    if-nez v7, :cond_16

    .line 338
    .line 339
    goto :goto_d

    .line 340
    :cond_16
    if-eq v5, v3, :cond_18

    .line 341
    .line 342
    check-cast v2, Ljava/util/Collection;

    .line 343
    .line 344
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 345
    .line 346
    .line 347
    move-result v2

    .line 348
    if-nez v2, :cond_18

    .line 349
    .line 350
    iget v2, v4, Lm1/a;->d:F

    .line 351
    .line 352
    cmpg-float v2, v2, v9

    .line 353
    .line 354
    if-gez v2, :cond_17

    .line 355
    .line 356
    goto :goto_c

    .line 357
    :cond_17
    const/4 v10, 0x0

    .line 358
    :goto_c
    invoke-static {v1, v10}, Lm1/a;->b(Lm1/l;Z)I

    .line 359
    .line 360
    .line 361
    move-result v2

    .line 362
    if-ltz v2, :cond_18

    .line 363
    .line 364
    if-ge v2, v3, :cond_18

    .line 365
    .line 366
    iput v2, v4, Lm1/a;->a:I

    .line 367
    .line 368
    iget-object v0, v0, Lm1/t;->q:Lh6/e;

    .line 369
    .line 370
    invoke-static {v0, v2}, Lh6/e;->B(Lh6/e;I)Lo1/k0;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    iput-object v0, v4, Lm1/a;->e:Ljava/lang/Object;

    .line 375
    .line 376
    :cond_18
    :goto_d
    iput v3, v4, Lm1/a;->c:I

    .line 377
    .line 378
    :cond_19
    :goto_e
    if-eqz p2, :cond_1a

    .line 379
    .line 380
    iget v0, v1, Lm1/l;->f:F

    .line 381
    .line 382
    iget-object v2, v1, Lm1/l;->i:Lt4/c;

    .line 383
    .line 384
    iget-object v1, v1, Lm1/l;->h:Lvy0/b0;

    .line 385
    .line 386
    invoke-virtual {v6, v0, v2, v1}, Lb81/a;->u(FLt4/c;Lvy0/b0;)V

    .line 387
    .line 388
    .line 389
    :cond_1a
    return-void
.end method

.method public final h()Lm1/l;
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/t;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lm1/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public final i(FLm1/l;)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lm1/t;->j:Z

    .line 2
    .line 3
    if-eqz v0, :cond_6

    .line 4
    .line 5
    iget-object v0, p2, Lm1/l;->k:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v1, p2, Lm1/l;->k:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iget-object v2, p0, Lm1/t;->a:Lm1/a;

    .line 16
    .line 17
    if-nez v0, :cond_5

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    cmpg-float v0, p1, v0

    .line 21
    .line 22
    if-gez v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x0

    .line 27
    :goto_0
    invoke-static {p2, v0}, Lm1/a;->b(Lm1/l;Z)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-ltz v3, :cond_5

    .line 32
    .line 33
    iget v4, p2, Lm1/l;->n:I

    .line 34
    .line 35
    if-ge v3, v4, :cond_5

    .line 36
    .line 37
    iget v4, v2, Lm1/a;->a:I

    .line 38
    .line 39
    if-eq v3, v4, :cond_3

    .line 40
    .line 41
    iget-boolean v4, v2, Lm1/a;->b:Z

    .line 42
    .line 43
    if-eq v4, v0, :cond_2

    .line 44
    .line 45
    const/4 v4, -0x1

    .line 46
    iput v4, v2, Lm1/a;->a:I

    .line 47
    .line 48
    iget-object v4, v2, Lm1/a;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v4, Lo1/k0;

    .line 51
    .line 52
    if-eqz v4, :cond_1

    .line 53
    .line 54
    invoke-interface {v4}, Lo1/k0;->cancel()V

    .line 55
    .line 56
    .line 57
    :cond_1
    const/4 v4, 0x0

    .line 58
    iput-object v4, v2, Lm1/a;->e:Ljava/lang/Object;

    .line 59
    .line 60
    :cond_2
    iput-boolean v0, v2, Lm1/a;->b:Z

    .line 61
    .line 62
    iput v3, v2, Lm1/a;->a:I

    .line 63
    .line 64
    iget-object p0, p0, Lm1/t;->q:Lh6/e;

    .line 65
    .line 66
    invoke-static {p0, v3}, Lh6/e;->B(Lh6/e;I)Lo1/k0;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    iput-object p0, v2, Lm1/a;->e:Ljava/lang/Object;

    .line 71
    .line 72
    :cond_3
    if-eqz v0, :cond_4

    .line 73
    .line 74
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    check-cast p0, Lm1/m;

    .line 79
    .line 80
    iget v0, p2, Lm1/l;->q:I

    .line 81
    .line 82
    iget v1, p0, Lm1/m;->o:I

    .line 83
    .line 84
    iget p0, p0, Lm1/m;->p:I

    .line 85
    .line 86
    add-int/2addr v1, p0

    .line 87
    add-int/2addr v1, v0

    .line 88
    iget p0, p2, Lm1/l;->m:I

    .line 89
    .line 90
    sub-int/2addr v1, p0

    .line 91
    int-to-float p0, v1

    .line 92
    neg-float p2, p1

    .line 93
    cmpg-float p0, p0, p2

    .line 94
    .line 95
    if-gez p0, :cond_5

    .line 96
    .line 97
    iget-object p0, v2, Lm1/a;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p0, Lo1/k0;

    .line 100
    .line 101
    if-eqz p0, :cond_5

    .line 102
    .line 103
    invoke-interface {p0}, Lo1/k0;->a()V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    check-cast p0, Lm1/m;

    .line 112
    .line 113
    iget p2, p2, Lm1/l;->l:I

    .line 114
    .line 115
    iget p0, p0, Lm1/m;->o:I

    .line 116
    .line 117
    sub-int/2addr p2, p0

    .line 118
    int-to-float p0, p2

    .line 119
    cmpg-float p0, p0, p1

    .line 120
    .line 121
    if-gez p0, :cond_5

    .line 122
    .line 123
    iget-object p0, v2, Lm1/a;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Lo1/k0;

    .line 126
    .line 127
    if-eqz p0, :cond_5

    .line 128
    .line 129
    invoke-interface {p0}, Lo1/k0;->a()V

    .line 130
    .line 131
    .line 132
    :cond_5
    :goto_1
    iput p1, v2, Lm1/a;->d:F

    .line 133
    .line 134
    :cond_6
    return-void
.end method

.method public final k(IIZ)V
    .locals 4

    .line 1
    iget-object v0, p0, Lm1/t;->e:Lm1/o;

    .line 2
    .line 3
    iget-object v1, v0, Lm1/o;->b:Ll2/g1;

    .line 4
    .line 5
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-ne v1, p1, :cond_0

    .line 11
    .line 12
    iget-object v1, v0, Lm1/o;->c:Ll2/g1;

    .line 13
    .line 14
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eq v1, p2, :cond_1

    .line 19
    .line 20
    :cond_0
    iget-object v1, p0, Lm1/t;->n:Landroidx/compose/foundation/lazy/layout/b;

    .line 21
    .line 22
    invoke-virtual {v1}, Landroidx/compose/foundation/lazy/layout/b;->e()V

    .line 23
    .line 24
    .line 25
    iput-object v2, v1, Landroidx/compose/foundation/lazy/layout/b;->b:Lbb/g0;

    .line 26
    .line 27
    const/4 v3, -0x1

    .line 28
    iput v3, v1, Landroidx/compose/foundation/lazy/layout/b;->c:I

    .line 29
    .line 30
    :cond_1
    invoke-virtual {v0, p1, p2}, Lm1/o;->a(II)V

    .line 31
    .line 32
    .line 33
    iput-object v2, v0, Lm1/o;->e:Ljava/lang/Object;

    .line 34
    .line 35
    if-eqz p3, :cond_3

    .line 36
    .line 37
    iget-object p0, p0, Lm1/t;->k:Lv3/h0;

    .line 38
    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    invoke-virtual {p0}, Lv3/h0;->l()V

    .line 42
    .line 43
    .line 44
    :cond_2
    return-void

    .line 45
    :cond_3
    iget-object p0, p0, Lm1/t;->s:Ll2/b1;

    .line 46
    .line 47
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method
