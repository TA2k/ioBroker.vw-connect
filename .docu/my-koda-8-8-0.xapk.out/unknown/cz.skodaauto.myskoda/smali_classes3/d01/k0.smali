.class public final Ld01/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld01/a0;

.field public final b:Ljava/lang/String;

.field public final c:Ld01/y;

.field public final d:Ld01/r0;

.field public final e:Ljp/ng;

.field public f:Ld01/h;


# direct methods
.method public constructor <init>(Ld01/j0;)V
    .locals 1

    .line 1
    const-string v0, "builder"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p1, Ld01/j0;->a:Ld01/a0;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iput-object v0, p0, Ld01/k0;->a:Ld01/a0;

    .line 14
    .line 15
    iget-object v0, p1, Ld01/j0;->b:Ljava/lang/String;

    .line 16
    .line 17
    iput-object v0, p0, Ld01/k0;->b:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v0, p1, Ld01/j0;->c:Ld01/x;

    .line 20
    .line 21
    invoke-virtual {v0}, Ld01/x;->j()Ld01/y;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, Ld01/k0;->c:Ld01/y;

    .line 26
    .line 27
    iget-object v0, p1, Ld01/j0;->d:Ld01/r0;

    .line 28
    .line 29
    iput-object v0, p0, Ld01/k0;->d:Ld01/r0;

    .line 30
    .line 31
    iget-object p1, p1, Ld01/j0;->e:Ljp/ng;

    .line 32
    .line 33
    iput-object p1, p0, Ld01/k0;->e:Ljp/ng;

    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "url == null"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0
.end method


# virtual methods
.method public final a()Ld01/h;
    .locals 1

    .line 1
    iget-object v0, p0, Ld01/k0;->f:Ld01/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Ld01/h;->n:Ld01/h;

    .line 6
    .line 7
    iget-object v0, p0, Ld01/k0;->c:Ld01/y;

    .line 8
    .line 9
    invoke-static {v0}, Ljp/qe;->b(Ld01/y;)Ld01/h;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Ld01/k0;->f:Ld01/h;

    .line 14
    .line 15
    :cond_0
    return-object v0
.end method

.method public final b()Ld01/j0;
    .locals 2

    .line 1
    new-instance v0, Ld01/j0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ld01/k0;->a:Ld01/a0;

    .line 7
    .line 8
    iput-object v1, v0, Ld01/j0;->a:Ld01/a0;

    .line 9
    .line 10
    iget-object v1, p0, Ld01/k0;->b:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v1, v0, Ld01/j0;->b:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v1, p0, Ld01/k0;->d:Ld01/r0;

    .line 15
    .line 16
    iput-object v1, v0, Ld01/j0;->d:Ld01/r0;

    .line 17
    .line 18
    iget-object v1, p0, Ld01/k0;->e:Ljp/ng;

    .line 19
    .line 20
    iput-object v1, v0, Ld01/j0;->e:Ljp/ng;

    .line 21
    .line 22
    iget-object p0, p0, Ld01/k0;->c:Ld01/y;

    .line 23
    .line 24
    invoke-virtual {p0}, Ld01/y;->g()Ld01/x;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    iput-object p0, v0, Ld01/j0;->c:Ld01/x;

    .line 29
    .line 30
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const/16 v1, 0x20

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "Request{method="

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Ld01/k0;->b:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v1, ", url="

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ld01/k0;->a:Ld01/a0;

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ld01/k0;->c:Ld01/y;

    .line 29
    .line 30
    invoke-virtual {v1}, Ld01/y;->size()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    const-string v2, ", headers=["

    .line 37
    .line 38
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const/4 v2, 0x0

    .line 46
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eqz v3, :cond_3

    .line 51
    .line 52
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    add-int/lit8 v4, v2, 0x1

    .line 57
    .line 58
    if-ltz v2, :cond_2

    .line 59
    .line 60
    check-cast v3, Llx0/l;

    .line 61
    .line 62
    iget-object v5, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v5, Ljava/lang/String;

    .line 65
    .line 66
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v3, Ljava/lang/String;

    .line 69
    .line 70
    if-lez v2, :cond_0

    .line 71
    .line 72
    const-string v2, ", "

    .line 73
    .line 74
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    :cond_0
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const/16 v2, 0x3a

    .line 81
    .line 82
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-static {v5}, Le01/e;->m(Ljava/lang/String;)Z

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    if-eqz v2, :cond_1

    .line 90
    .line 91
    const-string v3, "\u2588\u2588"

    .line 92
    .line 93
    :cond_1
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    move v2, v4

    .line 97
    goto :goto_0

    .line 98
    :cond_2
    invoke-static {}, Ljp/k1;->r()V

    .line 99
    .line 100
    .line 101
    const/4 p0, 0x0

    .line 102
    throw p0

    .line 103
    :cond_3
    const/16 v1, 0x5d

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    :cond_4
    sget-object v1, Le01/a;->a:Le01/a;

    .line 109
    .line 110
    iget-object p0, p0, Ld01/k0;->e:Ljp/ng;

    .line 111
    .line 112
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-nez v1, :cond_5

    .line 117
    .line 118
    const-string v1, ", tags="

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    :cond_5
    const/16 p0, 0x7d

    .line 127
    .line 128
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0
.end method
