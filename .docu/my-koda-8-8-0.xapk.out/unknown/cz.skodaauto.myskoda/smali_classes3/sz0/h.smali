.class public final Lsz0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lsz0/g;
.implements Luz0/l;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lkp/y8;

.field public final c:I

.field public final d:Ljava/util/List;

.field public final e:Ljava/util/HashSet;

.field public final f:[Ljava/lang/String;

.field public final g:[Lsz0/g;

.field public final h:[Ljava/util/List;

.field public final i:[Z

.field public final j:Ljava/util/Map;

.field public final k:[Lsz0/g;

.field public final l:Llx0/q;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lkp/y8;ILjava/util/List;Lsz0/a;)V
    .locals 1

    .line 1
    const-string v0, "serialName"

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
    iput-object p1, p0, Lsz0/h;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Lsz0/h;->b:Lkp/y8;

    .line 12
    .line 13
    iput p3, p0, Lsz0/h;->c:I

    .line 14
    .line 15
    iget-object p1, p5, Lsz0/a;->b:Ljava/util/List;

    .line 16
    .line 17
    iput-object p1, p0, Lsz0/h;->d:Ljava/util/List;

    .line 18
    .line 19
    iget-object p1, p5, Lsz0/a;->c:Ljava/util/ArrayList;

    .line 20
    .line 21
    const-string p2, "<this>"

    .line 22
    .line 23
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance p3, Ljava/util/HashSet;

    .line 27
    .line 28
    const/16 v0, 0xc

    .line 29
    .line 30
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-static {v0}, Lmx0/x;->k(I)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-direct {p3, v0}, Ljava/util/HashSet;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-static {p1, p3}, Lmx0/q;->u0(Ljava/lang/Iterable;Ljava/util/AbstractCollection;)V

    .line 42
    .line 43
    .line 44
    iput-object p3, p0, Lsz0/h;->e:Ljava/util/HashSet;

    .line 45
    .line 46
    const/4 p3, 0x0

    .line 47
    new-array v0, p3, [Ljava/lang/String;

    .line 48
    .line 49
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    check-cast p1, [Ljava/lang/String;

    .line 54
    .line 55
    iput-object p1, p0, Lsz0/h;->f:[Ljava/lang/String;

    .line 56
    .line 57
    iget-object v0, p5, Lsz0/a;->e:Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-static {v0}, Luz0/b1;->c(Ljava/util/List;)[Lsz0/g;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    iput-object v0, p0, Lsz0/h;->g:[Lsz0/g;

    .line 64
    .line 65
    iget-object v0, p5, Lsz0/a;->f:Ljava/util/ArrayList;

    .line 66
    .line 67
    new-array p3, p3, [Ljava/util/List;

    .line 68
    .line 69
    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p3

    .line 73
    check-cast p3, [Ljava/util/List;

    .line 74
    .line 75
    iput-object p3, p0, Lsz0/h;->h:[Ljava/util/List;

    .line 76
    .line 77
    iget-object p3, p5, Lsz0/a;->g:Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-static {p3}, Lmx0/q;->s0(Ljava/util/Collection;)[Z

    .line 80
    .line 81
    .line 82
    move-result-object p3

    .line 83
    iput-object p3, p0, Lsz0/h;->i:[Z

    .line 84
    .line 85
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    new-instance p2, Lky0/p;

    .line 89
    .line 90
    new-instance p3, Lmc/e;

    .line 91
    .line 92
    const/4 p5, 0x4

    .line 93
    invoke-direct {p3, p1, p5}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    const/4 p1, 0x2

    .line 97
    invoke-direct {p2, p3, p1}, Lky0/p;-><init>(Ljava/lang/Object;I)V

    .line 98
    .line 99
    .line 100
    new-instance p1, Ljava/util/ArrayList;

    .line 101
    .line 102
    const/16 p3, 0xa

    .line 103
    .line 104
    invoke-static {p2, p3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 105
    .line 106
    .line 107
    move-result p3

    .line 108
    invoke-direct {p1, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p2}, Lky0/p;->iterator()Ljava/util/Iterator;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    :goto_0
    move-object p3, p2

    .line 116
    check-cast p3, Lky0/b;

    .line 117
    .line 118
    iget-object p5, p3, Lky0/b;->f:Ljava/util/Iterator;

    .line 119
    .line 120
    invoke-interface {p5}, Ljava/util/Iterator;->hasNext()Z

    .line 121
    .line 122
    .line 123
    move-result p5

    .line 124
    if-eqz p5, :cond_0

    .line 125
    .line 126
    invoke-virtual {p3}, Lky0/b;->next()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    check-cast p3, Lmx0/v;

    .line 131
    .line 132
    iget-object p5, p3, Lmx0/v;->b:Ljava/lang/Object;

    .line 133
    .line 134
    iget p3, p3, Lmx0/v;->a:I

    .line 135
    .line 136
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 137
    .line 138
    .line 139
    move-result-object p3

    .line 140
    new-instance v0, Llx0/l;

    .line 141
    .line 142
    invoke-direct {v0, p5, p3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_0
    invoke-static {p1}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    iput-object p1, p0, Lsz0/h;->j:Ljava/util/Map;

    .line 154
    .line 155
    invoke-static {p4}, Luz0/b1;->c(Ljava/util/List;)[Lsz0/g;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    iput-object p1, p0, Lsz0/h;->k:[Lsz0/g;

    .line 160
    .line 161
    new-instance p1, Lr1/b;

    .line 162
    .line 163
    const/16 p2, 0xd

    .line 164
    .line 165
    invoke-direct {p1, p0, p2}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 166
    .line 167
    .line 168
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    iput-object p1, p0, Lsz0/h;->l:Llx0/q;

    .line 173
    .line 174
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->e:Ljava/util/HashSet;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final c(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lsz0/h;->j:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Integer;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, -0x3

    .line 22
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget p0, p0, Lsz0/h;->c:I

    .line 2
    .line 3
    return p0
.end method

.method public final e(I)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->f:[Ljava/lang/String;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_2

    .line 4
    :cond_0
    instance-of v0, p1, Lsz0/h;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_1
    move-object v0, p1

    .line 11
    check-cast v0, Lsz0/g;

    .line 12
    .line 13
    invoke-interface {v0}, Lsz0/g;->h()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    iget-object v3, p0, Lsz0/h;->a:Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_2

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_2
    check-cast p1, Lsz0/h;

    .line 27
    .line 28
    iget-object v2, p0, Lsz0/h;->k:[Lsz0/g;

    .line 29
    .line 30
    iget-object p1, p1, Lsz0/h;->k:[Lsz0/g;

    .line 31
    .line 32
    invoke-static {v2, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-nez p1, :cond_3

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_3
    invoke-interface {v0}, Lsz0/g;->d()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    iget v2, p0, Lsz0/h;->c:I

    .line 44
    .line 45
    if-eq v2, p1, :cond_4

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_4
    move p1, v1

    .line 49
    :goto_0
    if-ge p1, v2, :cond_7

    .line 50
    .line 51
    iget-object v3, p0, Lsz0/h;->g:[Lsz0/g;

    .line 52
    .line 53
    aget-object v4, v3, p1

    .line 54
    .line 55
    invoke-interface {v4}, Lsz0/g;->h()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    invoke-interface {v0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    invoke-interface {v5}, Lsz0/g;->h()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-nez v4, :cond_5

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_5
    aget-object v3, v3, p1

    .line 75
    .line 76
    invoke-interface {v3}, Lsz0/g;->getKind()Lkp/y8;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-interface {v0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    invoke-interface {v4}, Lsz0/g;->getKind()Lkp/y8;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    if-nez v3, :cond_6

    .line 93
    .line 94
    :goto_1
    return v1

    .line 95
    :cond_6
    add-int/lit8 p1, p1, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_7
    :goto_2
    const/4 p0, 0x1

    .line 99
    return p0
.end method

.method public final f(I)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->h:[Ljava/util/List;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    return-object p0
.end method

.method public final g(I)Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->g:[Lsz0/g;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    return-object p0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->d:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getKind()Lkp/y8;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->b:Lkp/y8;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->l:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final i(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/h;->i:[Z

    .line 2
    .line 3
    aget-boolean p0, p0, p1

    .line 4
    .line 5
    return p0
.end method

.method public final isInline()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Luz0/b1;->n(Lsz0/g;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
