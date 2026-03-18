.class public final Lh8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/y0;


# instance fields
.field public final d:Lh8/y0;

.field public e:Z

.field public final synthetic f:Lh8/c;


# direct methods
.method public constructor <init>(Lh8/c;Lh8/y0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/b;->f:Lh8/c;

    .line 5
    .line 6
    iput-object p2, p0, Lh8/b;->d:Lh8/y0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/b;->f:Lh8/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lh8/c;->i()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lh8/b;->d:Lh8/y0;

    .line 10
    .line 11
    invoke-interface {p0}, Lh8/y0;->a()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final c()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/b;->d:Lh8/y0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh8/y0;->c()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d(Lb81/d;Lz7/e;I)I
    .locals 11

    .line 1
    iget-object v0, p0, Lh8/b;->f:Lh8/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lh8/c;->i()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, -0x3

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    iget-boolean v1, p0, Lh8/b;->e:Z

    .line 12
    .line 13
    const/4 v3, 0x4

    .line 14
    const/4 v4, -0x4

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    iput v3, p2, Lkq/d;->e:I

    .line 18
    .line 19
    return v4

    .line 20
    :cond_1
    invoke-virtual {v0}, Lh8/c;->r()J

    .line 21
    .line 22
    .line 23
    move-result-wide v5

    .line 24
    iget-object v1, p0, Lh8/b;->d:Lh8/y0;

    .line 25
    .line 26
    invoke-interface {v1, p1, p2, p3}, Lh8/y0;->d(Lb81/d;Lz7/e;I)I

    .line 27
    .line 28
    .line 29
    move-result p3

    .line 30
    const/4 v1, -0x5

    .line 31
    const-wide/high16 v7, -0x8000000000000000L

    .line 32
    .line 33
    if-ne p3, v1, :cond_6

    .line 34
    .line 35
    iget-object p0, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lt7/o;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    iget p2, p0, Lt7/o;->J:I

    .line 43
    .line 44
    iget p3, p0, Lt7/o;->I:I

    .line 45
    .line 46
    if-nez p3, :cond_3

    .line 47
    .line 48
    if-eqz p2, :cond_2

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    return v1

    .line 52
    :cond_3
    :goto_0
    iget-wide v2, v0, Lh8/c;->h:J

    .line 53
    .line 54
    const-wide/16 v4, 0x0

    .line 55
    .line 56
    cmp-long v2, v2, v4

    .line 57
    .line 58
    const/4 v3, 0x0

    .line 59
    if-eqz v2, :cond_4

    .line 60
    .line 61
    move p3, v3

    .line 62
    :cond_4
    iget-wide v4, v0, Lh8/c;->i:J

    .line 63
    .line 64
    cmp-long v0, v4, v7

    .line 65
    .line 66
    if-eqz v0, :cond_5

    .line 67
    .line 68
    move p2, v3

    .line 69
    :cond_5
    invoke-virtual {p0}, Lt7/o;->a()Lt7/n;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    iput p3, p0, Lt7/n;->H:I

    .line 74
    .line 75
    iput p2, p0, Lt7/n;->I:I

    .line 76
    .line 77
    new-instance p2, Lt7/o;

    .line 78
    .line 79
    invoke-direct {p2, p0}, Lt7/o;-><init>(Lt7/n;)V

    .line 80
    .line 81
    .line 82
    iput-object p2, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 83
    .line 84
    return v1

    .line 85
    :cond_6
    iget-wide v0, v0, Lh8/c;->i:J

    .line 86
    .line 87
    cmp-long p1, v0, v7

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    if-ne p3, v4, :cond_7

    .line 92
    .line 93
    iget-wide v9, p2, Lz7/e;->j:J

    .line 94
    .line 95
    cmp-long p1, v9, v0

    .line 96
    .line 97
    if-gez p1, :cond_8

    .line 98
    .line 99
    :cond_7
    if-ne p3, v2, :cond_9

    .line 100
    .line 101
    cmp-long p1, v5, v7

    .line 102
    .line 103
    if-nez p1, :cond_9

    .line 104
    .line 105
    iget-boolean p1, p2, Lz7/e;->i:Z

    .line 106
    .line 107
    if-nez p1, :cond_9

    .line 108
    .line 109
    :cond_8
    invoke-virtual {p2}, Lz7/e;->m()V

    .line 110
    .line 111
    .line 112
    iput v3, p2, Lkq/d;->e:I

    .line 113
    .line 114
    const/4 p1, 0x1

    .line 115
    iput-boolean p1, p0, Lh8/b;->e:Z

    .line 116
    .line 117
    return v4

    .line 118
    :cond_9
    return p3
.end method

.method public final l(J)I
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/b;->f:Lh8/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lh8/c;->i()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, -0x3

    .line 10
    return p0

    .line 11
    :cond_0
    iget-object p0, p0, Lh8/b;->d:Lh8/y0;

    .line 12
    .line 13
    invoke-interface {p0, p1, p2}, Lh8/y0;->l(J)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method
