.class public final Lj11/y;
.super Lj11/s;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lj11/s;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj11/y;->g:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lb11/a;)V
    .locals 10

    .line 1
    iget v0, p1, Lb11/a;->e:I

    .line 2
    .line 3
    if-nez v0, :cond_7

    .line 4
    .line 5
    iget-object p1, p1, Lb11/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p1, Lb11/b;

    .line 8
    .line 9
    iget-object v0, p0, Lj11/y;->g:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p0}, Lj11/s;->d()Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/4 v3, 0x1

    .line 20
    const/4 v4, 0x0

    .line 21
    if-ne v2, v3, :cond_0

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lj11/w;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move-object v1, v4

    .line 32
    :goto_0
    iget-object p1, p1, Lb11/b;->a:Lil/g;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    if-eqz v0, :cond_6

    .line 38
    .line 39
    new-instance v2, Lr21/b;

    .line 40
    .line 41
    new-instance v3, Lr21/a;

    .line 42
    .line 43
    invoke-direct {v3, p1, v0}, Lr21/a;-><init>(Lil/g;Ljava/lang/CharSequence;)V

    .line 44
    .line 45
    .line 46
    invoke-direct {v2, v0, v3}, Lr21/b;-><init>(Ljava/lang/CharSequence;Lr21/a;)V

    .line 47
    .line 48
    .line 49
    move-object p1, p0

    .line 50
    :goto_1
    invoke-virtual {v2}, Lr21/b;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-eqz v3, :cond_5

    .line 55
    .line 56
    invoke-virtual {v2}, Lr21/b;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    check-cast v3, Lr21/d;

    .line 61
    .line 62
    if-ne p1, p0, :cond_1

    .line 63
    .line 64
    invoke-virtual {v2}, Lr21/b;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    if-nez v5, :cond_1

    .line 69
    .line 70
    instance-of v5, v3, Ls21/a;

    .line 71
    .line 72
    if-nez v5, :cond_1

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_1
    invoke-interface {v3}, Lr21/d;->getBeginIndex()I

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    invoke-interface {v3}, Lr21/d;->getEndIndex()I

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    invoke-virtual {v0, v5, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v7

    .line 87
    new-instance v8, Lj11/y;

    .line 88
    .line 89
    invoke-direct {v8, v7}, Lj11/y;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    if-eqz v1, :cond_2

    .line 93
    .line 94
    sub-int/2addr v6, v5

    .line 95
    iget v7, v1, Lj11/w;->a:I

    .line 96
    .line 97
    new-instance v9, Lj11/w;

    .line 98
    .line 99
    invoke-direct {v9, v7, v5, v6}, Lj11/w;-><init>(III)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v8, v9}, Lj11/s;->b(Lj11/w;)V

    .line 103
    .line 104
    .line 105
    :cond_2
    instance-of v5, v3, Ls21/a;

    .line 106
    .line 107
    if-eqz v5, :cond_4

    .line 108
    .line 109
    check-cast v3, Ls21/a;

    .line 110
    .line 111
    iget-object v5, v8, Lj11/y;->g:Ljava/lang/String;

    .line 112
    .line 113
    iget-object v3, v3, Ls21/a;->a:Lr21/c;

    .line 114
    .line 115
    sget-object v6, Lr21/c;->e:Lr21/c;

    .line 116
    .line 117
    if-ne v3, v6, :cond_3

    .line 118
    .line 119
    const-string v3, "mailto:"

    .line 120
    .line 121
    invoke-static {v3, v5}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    :cond_3
    new-instance v3, Lj11/o;

    .line 126
    .line 127
    invoke-direct {v3, v5, v4}, Lj11/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v3, v8}, Lj11/s;->c(Lj11/s;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v8}, Lj11/s;->d()Ljava/util/List;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    invoke-virtual {v3, v5}, Lj11/s;->g(Ljava/util/List;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p1, v3}, Lj11/s;->e(Lj11/s;)V

    .line 141
    .line 142
    .line 143
    move-object p1, v3

    .line 144
    goto :goto_1

    .line 145
    :cond_4
    invoke-virtual {p1, v8}, Lj11/s;->e(Lj11/s;)V

    .line 146
    .line 147
    .line 148
    move-object p1, v8

    .line 149
    goto :goto_1

    .line 150
    :cond_5
    invoke-virtual {p0}, Lj11/s;->i()V

    .line 151
    .line 152
    .line 153
    return-void

    .line 154
    :cond_6
    new-instance p0, Ljava/lang/NullPointerException;

    .line 155
    .line 156
    const-string p1, "input must not be null"

    .line 157
    .line 158
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_7
    :goto_2
    return-void
.end method

.method public final h()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "literal="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lj11/y;->g:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
