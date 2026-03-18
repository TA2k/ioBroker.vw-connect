.class public final Lwz0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final d:Lvz0/d;

.field public final e:Lwz0/z;

.field public final f:Lqz0/a;

.field public g:Z

.field public h:Z


# direct methods
.method public constructor <init>(Lvz0/d;Lwz0/z;Lqz0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwz0/n;->d:Lvz0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lwz0/n;->e:Lwz0/z;

    .line 7
    .line 8
    iput-object p3, p0, Lwz0/n;->f:Lqz0/a;

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    iput-boolean p1, p0, Lwz0/n;->g:Z

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 7

    .line 1
    iget-boolean v0, p0, Lwz0/n;->h:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    iget-object v0, p0, Lwz0/n;->e:Lwz0/z;

    .line 8
    .line 9
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/16 v3, 0xa

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x1

    .line 17
    const/16 v6, 0x9

    .line 18
    .line 19
    if-ne v2, v6, :cond_3

    .line 20
    .line 21
    iput-boolean v5, p0, Lwz0/n;->h:Z

    .line 22
    .line 23
    invoke-virtual {v0, v6}, Lo8/j;->g(B)B

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eq p0, v3, :cond_2

    .line 31
    .line 32
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    const/16 v2, 0x8

    .line 37
    .line 38
    if-eq p0, v2, :cond_1

    .line 39
    .line 40
    invoke-virtual {v0}, Lo8/j;->p()V

    .line 41
    .line 42
    .line 43
    return v1

    .line 44
    :cond_1
    const-string p0, "There is a start of the new array after the one parsed to sequence. ARRAY_WRAPPED mode doesn\'t merge consecutive arrays.\nIf you need to parse a stream of arrays, please use WHITESPACE_SEPARATED mode instead."

    .line 45
    .line 46
    const/4 v2, 0x6

    .line 47
    invoke-static {v0, p0, v1, v4, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 48
    .line 49
    .line 50
    throw v4

    .line 51
    :cond_2
    return v1

    .line 52
    :cond_3
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eq v1, v3, :cond_4

    .line 57
    .line 58
    return v5

    .line 59
    :cond_4
    iget-boolean p0, p0, Lwz0/n;->h:Z

    .line 60
    .line 61
    if-nez p0, :cond_7

    .line 62
    .line 63
    invoke-static {v6}, Lwz0/p;->s(B)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    iget v1, v0, Lo8/j;->b:I

    .line 68
    .line 69
    add-int/lit8 v2, v1, -0x1

    .line 70
    .line 71
    iget-object v3, v0, Lwz0/z;->h:Lwz0/c;

    .line 72
    .line 73
    iget v5, v3, Lwz0/c;->e:I

    .line 74
    .line 75
    if-eq v1, v5, :cond_6

    .line 76
    .line 77
    if-gez v2, :cond_5

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_5
    iget-object v1, v3, Lwz0/c;->d:[C

    .line 81
    .line 82
    aget-char v1, v1, v2

    .line 83
    .line 84
    invoke-static {v1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    goto :goto_1

    .line 89
    :cond_6
    :goto_0
    const-string v1, "EOF"

    .line 90
    .line 91
    :goto_1
    const-string v3, ", but had \'"

    .line 92
    .line 93
    const-string v5, "\' instead"

    .line 94
    .line 95
    const-string v6, "Expected "

    .line 96
    .line 97
    invoke-static {v6, p0, v3, v1, v5}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const/4 v1, 0x4

    .line 102
    invoke-static {v0, p0, v2, v4, v1}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 103
    .line 104
    .line 105
    throw v4

    .line 106
    :cond_7
    return v5
.end method

.method public final next()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-boolean v0, p0, Lwz0/n;->g:Z

    .line 2
    .line 3
    iget-object v4, p0, Lwz0/n;->e:Lwz0/z;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-boolean v0, p0, Lwz0/n;->g:Z

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/16 v0, 0x2c

    .line 12
    .line 13
    invoke-virtual {v4, v0}, Lwz0/z;->h(C)V

    .line 14
    .line 15
    .line 16
    :goto_0
    new-instance v1, Lwz0/a0;

    .line 17
    .line 18
    sget-object v3, Lwz0/f0;->f:Lwz0/f0;

    .line 19
    .line 20
    iget-object v0, p0, Lwz0/n;->f:Lqz0/a;

    .line 21
    .line 22
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    const/4 v6, 0x0

    .line 27
    iget-object v2, p0, Lwz0/n;->d:Lvz0/d;

    .line 28
    .line 29
    invoke-direct/range {v1 .. v6}, Lwz0/a0;-><init>(Lvz0/d;Lwz0/f0;Lo8/j;Lsz0/g;Lgr/f;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, v0}, Lwz0/a0;->d(Lqz0/a;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public final remove()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "Operation is not supported for read-only collection"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
