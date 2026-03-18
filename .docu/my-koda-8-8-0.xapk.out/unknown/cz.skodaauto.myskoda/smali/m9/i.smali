.class public abstract Lm9/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll9/e;


# instance fields
.field public final a:Ljava/util/ArrayDeque;

.field public final b:Ljava/util/ArrayDeque;

.field public final c:Ljava/util/ArrayDeque;

.field public d:Lm9/h;

.field public e:J

.field public f:J

.field public g:J


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayDeque;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lm9/i;->a:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    move v1, v0

    .line 13
    :goto_0
    const/16 v2, 0xa

    .line 14
    .line 15
    if-ge v1, v2, :cond_0

    .line 16
    .line 17
    iget-object v2, p0, Lm9/i;->a:Ljava/util/ArrayDeque;

    .line 18
    .line 19
    new-instance v3, Lm9/h;

    .line 20
    .line 21
    const/4 v4, 0x1

    .line 22
    invoke-direct {v3, v4}, Lz7/e;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2, v3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v1, Ljava/util/ArrayDeque;

    .line 32
    .line 33
    invoke-direct {v1}, Ljava/util/ArrayDeque;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v1, p0, Lm9/i;->b:Ljava/util/ArrayDeque;

    .line 37
    .line 38
    :goto_1
    const/4 v1, 0x2

    .line 39
    if-ge v0, v1, :cond_1

    .line 40
    .line 41
    iget-object v1, p0, Lm9/i;->b:Ljava/util/ArrayDeque;

    .line 42
    .line 43
    new-instance v2, Ll9/c;

    .line 44
    .line 45
    new-instance v3, Lgr/k;

    .line 46
    .line 47
    const/16 v4, 0xe

    .line 48
    .line 49
    invoke-direct {v3, p0, v4}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    invoke-direct {v2}, Ll9/c;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v3, v2, Ll9/c;->k:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-virtual {v1, v2}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    add-int/lit8 v0, v0, 0x1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    new-instance v0, Ljava/util/ArrayDeque;

    .line 64
    .line 65
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 66
    .line 67
    .line 68
    iput-object v0, p0, Lm9/i;->c:Ljava/util/ArrayDeque;

    .line 69
    .line 70
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    iput-wide v0, p0, Lm9/i;->g:J

    .line 76
    .line 77
    return-void
.end method


# virtual methods
.method public final a(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lm9/i;->e:J

    .line 2
    .line 3
    return-void
.end method

.method public b()V
    .locals 0

    .line 1
    return-void
.end method

.method public bridge synthetic c()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lm9/i;->i()Ll9/c;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lm9/i;->g:J

    .line 2
    .line 3
    return-void
.end method

.method public final e(Ll9/g;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lm9/i;->d:Lm9/h;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 9
    .line 10
    .line 11
    check-cast p1, Lm9/h;

    .line 12
    .line 13
    const/4 v0, 0x4

    .line 14
    invoke-virtual {p1, v0}, Lkq/d;->c(I)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    iget-wide v0, p1, Lz7/e;->j:J

    .line 21
    .line 22
    const-wide/high16 v2, -0x8000000000000000L

    .line 23
    .line 24
    cmp-long v2, v0, v2

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    iget-wide v2, p0, Lm9/i;->g:J

    .line 29
    .line 30
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    cmp-long v4, v2, v4

    .line 36
    .line 37
    if-eqz v4, :cond_1

    .line 38
    .line 39
    cmp-long v0, v0, v2

    .line 40
    .line 41
    if-gez v0, :cond_1

    .line 42
    .line 43
    invoke-virtual {p1}, Lz7/e;->m()V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lm9/i;->a:Ljava/util/ArrayDeque;

    .line 47
    .line 48
    invoke-virtual {v0, p1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    iget-wide v0, p0, Lm9/i;->f:J

    .line 53
    .line 54
    const-wide/16 v2, 0x1

    .line 55
    .line 56
    add-long/2addr v2, v0

    .line 57
    iput-wide v2, p0, Lm9/i;->f:J

    .line 58
    .line 59
    iput-wide v0, p1, Lm9/h;->n:J

    .line 60
    .line 61
    iget-object v0, p0, Lm9/i;->c:Ljava/util/ArrayDeque;

    .line 62
    .line 63
    invoke-virtual {v0, p1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    :goto_1
    const/4 p1, 0x0

    .line 67
    iput-object p1, p0, Lm9/i;->d:Lm9/h;

    .line 68
    .line 69
    return-void
.end method

.method public final f()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lm9/i;->d:Lm9/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lm9/i;->a:Ljava/util/ArrayDeque;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return-object p0

    .line 21
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->pollFirst()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lm9/h;

    .line 26
    .line 27
    iput-object v0, p0, Lm9/i;->d:Lm9/h;

    .line 28
    .line 29
    return-object v0
.end method

.method public flush()V
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lm9/i;->f:J

    .line 4
    .line 5
    iput-wide v0, p0, Lm9/i;->e:J

    .line 6
    .line 7
    :goto_0
    iget-object v0, p0, Lm9/i;->c:Ljava/util/ArrayDeque;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object v2, p0, Lm9/i;->a:Ljava/util/ArrayDeque;

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lm9/h;

    .line 22
    .line 23
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v0}, Lz7/e;->m()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v2, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v0, p0, Lm9/i;->d:Lm9/h;

    .line 33
    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {v0}, Lz7/e;->m()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v2, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    iput-object v0, p0, Lm9/i;->d:Lm9/h;

    .line 44
    .line 45
    :cond_1
    return-void
.end method

.method public abstract g()Laq/m;
.end method

.method public abstract h(Lm9/h;)V
.end method

.method public i()Ll9/c;
    .locals 6

    .line 1
    iget-object v0, p0, Lm9/i;->b:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    :goto_0
    iget-object v1, p0, Lm9/i;->c:Ljava/util/ArrayDeque;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_3

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Lm9/h;

    .line 23
    .line 24
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 25
    .line 26
    iget-wide v2, v2, Lz7/e;->j:J

    .line 27
    .line 28
    iget-wide v4, p0, Lm9/i;->e:J

    .line 29
    .line 30
    cmp-long v2, v2, v4

    .line 31
    .line 32
    if-gtz v2, :cond_3

    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lm9/h;

    .line 39
    .line 40
    const/4 v2, 0x4

    .line 41
    invoke-virtual {v1, v2}, Lkq/d;->c(I)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    iget-object v4, p0, Lm9/i;->a:Ljava/util/ArrayDeque;

    .line 46
    .line 47
    if-eqz v3, :cond_1

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->pollFirst()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ll9/c;

    .line 54
    .line 55
    invoke-virtual {p0, v2}, Lkq/d;->a(I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1}, Lz7/e;->m()V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v4, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_1
    invoke-virtual {p0, v1}, Lm9/i;->h(Lm9/h;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Lm9/i;->j()Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_2

    .line 73
    .line 74
    invoke-virtual {p0}, Lm9/i;->g()Laq/m;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->pollFirst()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    check-cast v0, Ll9/c;

    .line 83
    .line 84
    iget-wide v2, v1, Lz7/e;->j:J

    .line 85
    .line 86
    iput-wide v2, v0, Lz7/f;->f:J

    .line 87
    .line 88
    iput-object p0, v0, Ll9/c;->h:Ll9/d;

    .line 89
    .line 90
    iput-wide v2, v0, Ll9/c;->i:J

    .line 91
    .line 92
    invoke-virtual {v1}, Lz7/e;->m()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v4, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    return-object v0

    .line 99
    :cond_2
    invoke-virtual {v1}, Lz7/e;->m()V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v4, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_3
    :goto_1
    const/4 p0, 0x0

    .line 107
    return-object p0
.end method

.method public abstract j()Z
.end method
