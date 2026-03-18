.class public final Lh01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# static fields
.field public static final a:Lh01/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh01/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh01/a;->a:Lh01/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 8

    .line 1
    check-cast p1, Li01/f;

    .line 2
    .line 3
    iget-object p0, p1, Li01/f;->a:Lh01/o;

    .line 4
    .line 5
    monitor-enter p0

    .line 6
    :try_start_0
    iget-boolean v0, p0, Lh01/o;->s:Z

    .line 7
    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    iget-boolean v0, p0, Lh01/o;->p:Z

    .line 11
    .line 12
    if-nez v0, :cond_2

    .line 13
    .line 14
    iget-boolean v0, p0, Lh01/o;->o:Z

    .line 15
    .line 16
    if-nez v0, :cond_2

    .line 17
    .line 18
    iget-boolean v0, p0, Lh01/o;->r:Z

    .line 19
    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    iget-boolean v0, p0, Lh01/o;->q:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 23
    .line 24
    if-nez v0, :cond_2

    .line 25
    .line 26
    monitor-exit p0

    .line 27
    iget-object v0, p0, Lh01/o;->k:Lh01/h;

    .line 28
    .line 29
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-interface {v0}, Lh01/h;->a()Lh01/p;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    iget-object v2, p0, Lh01/o;->d:Ld01/h0;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    iget v3, p1, Li01/f;->g:I

    .line 42
    .line 43
    iget-object v4, v1, Lh01/p;->h:Lgw0/c;

    .line 44
    .line 45
    iget-object v5, v1, Lh01/p;->i:Lk01/p;

    .line 46
    .line 47
    if-eqz v5, :cond_0

    .line 48
    .line 49
    new-instance v3, Lk01/q;

    .line 50
    .line 51
    invoke-direct {v3, v2, v1, p1, v5}, Lk01/q;-><init>(Ld01/h0;Lh01/p;Li01/f;Lk01/p;)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    iget-object v5, v1, Lh01/p;->e:Ljava/net/Socket;

    .line 56
    .line 57
    invoke-virtual {v5, v3}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 58
    .line 59
    .line 60
    iget-object v5, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v5, Lu01/b0;

    .line 63
    .line 64
    iget-object v5, v5, Lu01/b0;->d:Lu01/h0;

    .line 65
    .line 66
    invoke-interface {v5}, Lu01/h0;->timeout()Lu01/j0;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    int-to-long v6, v3

    .line 71
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 72
    .line 73
    invoke-virtual {v5, v6, v7, v3}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 74
    .line 75
    .line 76
    iget-object v5, v4, Lgw0/c;->g:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v5, Lu01/a0;

    .line 79
    .line 80
    iget-object v5, v5, Lu01/a0;->d:Lu01/f0;

    .line 81
    .line 82
    invoke-interface {v5}, Lu01/f0;->timeout()Lu01/j0;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    iget v6, p1, Li01/f;->h:I

    .line 87
    .line 88
    int-to-long v6, v6

    .line 89
    invoke-virtual {v5, v6, v7, v3}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 90
    .line 91
    .line 92
    new-instance v3, Lj01/f;

    .line 93
    .line 94
    invoke-direct {v3, v2, v1, v4}, Lj01/f;-><init>(Ld01/h0;Li01/c;Lgw0/c;)V

    .line 95
    .line 96
    .line 97
    :goto_0
    new-instance v1, Lh01/g;

    .line 98
    .line 99
    invoke-direct {v1, p0, v0, v3}, Lh01/g;-><init>(Lh01/o;Lh01/h;Li01/d;)V

    .line 100
    .line 101
    .line 102
    iput-object v1, p0, Lh01/o;->n:Lh01/g;

    .line 103
    .line 104
    iput-object v1, p0, Lh01/o;->u:Lh01/g;

    .line 105
    .line 106
    monitor-enter p0

    .line 107
    const/4 v0, 0x1

    .line 108
    :try_start_1
    iput-boolean v0, p0, Lh01/o;->o:Z

    .line 109
    .line 110
    iput-boolean v0, p0, Lh01/o;->p:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 111
    .line 112
    monitor-exit p0

    .line 113
    iget-boolean p0, p0, Lh01/o;->t:Z

    .line 114
    .line 115
    if-nez p0, :cond_1

    .line 116
    .line 117
    const/4 p0, 0x0

    .line 118
    const/16 v0, 0x3d

    .line 119
    .line 120
    const/4 v2, 0x0

    .line 121
    invoke-static {p1, v2, v1, p0, v0}, Li01/f;->a(Li01/f;ILh01/g;Ld01/k0;I)Li01/f;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    iget-object p1, p1, Li01/f;->e:Ld01/k0;

    .line 126
    .line 127
    invoke-virtual {p0, p1}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0

    .line 132
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 133
    .line 134
    const-string p1, "Canceled"

    .line 135
    .line 136
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :catchall_0
    move-exception p1

    .line 141
    monitor-exit p0

    .line 142
    throw p1

    .line 143
    :catchall_1
    move-exception p1

    .line 144
    goto :goto_1

    .line 145
    :cond_2
    :try_start_2
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    const-string v0, "Check failed."

    .line 148
    .line 149
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw p1

    .line 153
    :cond_3
    const-string p1, "released"

    .line 154
    .line 155
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 156
    .line 157
    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 161
    :goto_1
    monitor-exit p0

    .line 162
    throw p1
.end method
