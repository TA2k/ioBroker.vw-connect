.class public final Lo1/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final s:J

.field public static final synthetic t:I


# instance fields
.field public final a:Lvy0/b0;

.field public final b:Le3/w;

.field public final c:Lmc/e;

.field public d:Lc1/a0;

.field public e:Lc1/a0;

.field public f:Lc1/a0;

.field public g:Z

.field public final h:Ll2/j1;

.field public final i:Ll2/j1;

.field public final j:Ll2/j1;

.field public final k:Ll2/j1;

.field public l:J

.field public m:J

.field public n:Lh3/c;

.field public final o:Lc1/c;

.field public final p:Lc1/c;

.field public final q:Ll2/j1;

.field public r:J


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const v0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    int-to-long v0, v0

    .line 5
    const/16 v2, 0x20

    .line 6
    .line 7
    shl-long v2, v0, v2

    .line 8
    .line 9
    const-wide v4, 0xffffffffL

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    and-long/2addr v0, v4

    .line 15
    or-long/2addr v0, v2

    .line 16
    sput-wide v0, Lo1/t;->s:J

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>(Lvy0/b0;Le3/w;Lmc/e;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo1/t;->a:Lvy0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lo1/t;->b:Le3/w;

    .line 7
    .line 8
    iput-object p3, p0, Lo1/t;->c:Lmc/e;

    .line 9
    .line 10
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 13
    .line 14
    .line 15
    move-result-object p3

    .line 16
    iput-object p3, p0, Lo1/t;->h:Ll2/j1;

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 19
    .line 20
    .line 21
    move-result-object p3

    .line 22
    iput-object p3, p0, Lo1/t;->i:Ll2/j1;

    .line 23
    .line 24
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    iput-object p3, p0, Lo1/t;->j:Ll2/j1;

    .line 29
    .line 30
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lo1/t;->k:Ll2/j1;

    .line 35
    .line 36
    sget-wide v0, Lo1/t;->s:J

    .line 37
    .line 38
    iput-wide v0, p0, Lo1/t;->l:J

    .line 39
    .line 40
    const-wide/16 v2, 0x0

    .line 41
    .line 42
    iput-wide v2, p0, Lo1/t;->m:J

    .line 43
    .line 44
    const/4 p1, 0x0

    .line 45
    if-eqz p2, :cond_0

    .line 46
    .line 47
    invoke-interface {p2}, Le3/w;->a()Lh3/c;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    move-object p2, p1

    .line 53
    :goto_0
    iput-object p2, p0, Lo1/t;->n:Lh3/c;

    .line 54
    .line 55
    new-instance p2, Lc1/c;

    .line 56
    .line 57
    new-instance p3, Lt4/j;

    .line 58
    .line 59
    invoke-direct {p3, v2, v3}, Lt4/j;-><init>(J)V

    .line 60
    .line 61
    .line 62
    sget-object v4, Lc1/d;->p:Lc1/b2;

    .line 63
    .line 64
    const/16 v5, 0xc

    .line 65
    .line 66
    invoke-direct {p2, p3, v4, p1, v5}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 67
    .line 68
    .line 69
    iput-object p2, p0, Lo1/t;->o:Lc1/c;

    .line 70
    .line 71
    new-instance p2, Lc1/c;

    .line 72
    .line 73
    const/high16 p3, 0x3f800000    # 1.0f

    .line 74
    .line 75
    invoke-static {p3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 76
    .line 77
    .line 78
    move-result-object p3

    .line 79
    sget-object v4, Lc1/d;->j:Lc1/b2;

    .line 80
    .line 81
    invoke-direct {p2, p3, v4, p1, v5}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 82
    .line 83
    .line 84
    iput-object p2, p0, Lo1/t;->p:Lc1/c;

    .line 85
    .line 86
    new-instance p1, Lt4/j;

    .line 87
    .line 88
    invoke-direct {p1, v2, v3}, Lt4/j;-><init>(J)V

    .line 89
    .line 90
    .line 91
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    iput-object p1, p0, Lo1/t;->q:Ll2/j1;

    .line 96
    .line 97
    iput-wide v0, p0, Lo1/t;->r:J

    .line 98
    .line 99
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 10

    .line 1
    iget-object v4, p0, Lo1/t;->n:Lh3/c;

    .line 2
    .line 3
    iget-object v3, p0, Lo1/t;->d:Lc1/a0;

    .line 4
    .line 5
    iget-object v0, p0, Lo1/t;->i:Ll2/j1;

    .line 6
    .line 7
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v7, 0x3

    .line 18
    iget-object v8, p0, Lo1/t;->a:Lvy0/b0;

    .line 19
    .line 20
    const/4 v9, 0x0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    if-nez v4, :cond_1

    .line 26
    .line 27
    :cond_0
    move-object v2, p0

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 v0, 0x1

    .line 30
    invoke-virtual {p0, v0}, Lo1/t;->d(Z)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lo1/t;->b()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    xor-int/lit8 v1, v0, 0x1

    .line 38
    .line 39
    if-nez v0, :cond_2

    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    invoke-virtual {v4, v0}, Lh3/c;->h(F)V

    .line 43
    .line 44
    .line 45
    :cond_2
    new-instance v0, Lau0/b;

    .line 46
    .line 47
    const/4 v5, 0x0

    .line 48
    const/4 v6, 0x6

    .line 49
    move-object v2, p0

    .line 50
    invoke-direct/range {v0 .. v6}, Lau0/b;-><init>(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 51
    .line 52
    .line 53
    invoke-static {v8, v9, v9, v0, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :goto_0
    invoke-virtual {v2}, Lo1/t;->b()Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p0, :cond_4

    .line 62
    .line 63
    if-eqz v4, :cond_3

    .line 64
    .line 65
    const/high16 p0, 0x3f800000    # 1.0f

    .line 66
    .line 67
    invoke-virtual {v4, p0}, Lh3/c;->h(F)V

    .line 68
    .line 69
    .line 70
    :cond_3
    new-instance p0, Lo1/r;

    .line 71
    .line 72
    const/4 v0, 0x0

    .line 73
    invoke-direct {p0, v2, v9, v0}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 74
    .line 75
    .line 76
    invoke-static {v8, v9, v9, p0, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 77
    .line 78
    .line 79
    :cond_4
    return-void
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/t;->j:Ll2/j1;

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

.method public final c()V
    .locals 6

    .line 1
    iget-object v0, p0, Lo1/t;->h:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x3

    .line 14
    iget-object v2, p0, Lo1/t;->a:Lvy0/b0;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0, v3}, Lo1/t;->f(Z)V

    .line 21
    .line 22
    .line 23
    new-instance v0, Lo1/r;

    .line 24
    .line 25
    const/4 v5, 0x2

    .line 26
    invoke-direct {v0, p0, v4, v5}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {v2, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    :cond_0
    iget-object v0, p0, Lo1/t;->i:Ll2/j1;

    .line 33
    .line 34
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Ljava/lang/Boolean;

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0, v3}, Lo1/t;->d(Z)V

    .line 47
    .line 48
    .line 49
    new-instance v0, Lo1/r;

    .line 50
    .line 51
    const/4 v5, 0x3

    .line 52
    invoke-direct {v0, p0, v4, v5}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    invoke-static {v2, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    :cond_1
    invoke-virtual {p0}, Lo1/t;->b()Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-eqz v0, :cond_2

    .line 63
    .line 64
    invoke-virtual {p0, v3}, Lo1/t;->e(Z)V

    .line 65
    .line 66
    .line 67
    new-instance v0, Lo1/r;

    .line 68
    .line 69
    const/4 v5, 0x4

    .line 70
    invoke-direct {v0, p0, v4, v5}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    invoke-static {v2, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 74
    .line 75
    .line 76
    :cond_2
    iput-boolean v3, p0, Lo1/t;->g:Z

    .line 77
    .line 78
    const-wide/16 v0, 0x0

    .line 79
    .line 80
    invoke-virtual {p0, v0, v1}, Lo1/t;->g(J)V

    .line 81
    .line 82
    .line 83
    sget-wide v0, Lo1/t;->s:J

    .line 84
    .line 85
    iput-wide v0, p0, Lo1/t;->l:J

    .line 86
    .line 87
    iget-object v0, p0, Lo1/t;->n:Lh3/c;

    .line 88
    .line 89
    if-eqz v0, :cond_3

    .line 90
    .line 91
    iget-object v1, p0, Lo1/t;->b:Le3/w;

    .line 92
    .line 93
    if-eqz v1, :cond_3

    .line 94
    .line 95
    invoke-interface {v1, v0}, Le3/w;->b(Lh3/c;)V

    .line 96
    .line 97
    .line 98
    :cond_3
    iput-object v4, p0, Lo1/t;->n:Lh3/c;

    .line 99
    .line 100
    iput-object v4, p0, Lo1/t;->d:Lc1/a0;

    .line 101
    .line 102
    iput-object v4, p0, Lo1/t;->f:Lc1/a0;

    .line 103
    .line 104
    iput-object v4, p0, Lo1/t;->e:Lc1/a0;

    .line 105
    .line 106
    return-void
.end method

.method public final d(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/t;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final e(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/t;->j:Ll2/j1;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final f(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/t;->h:Ll2/j1;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final g(J)V
    .locals 1

    .line 1
    new-instance v0, Lt4/j;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Lt4/j;-><init>(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lo1/t;->q:Ll2/j1;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
