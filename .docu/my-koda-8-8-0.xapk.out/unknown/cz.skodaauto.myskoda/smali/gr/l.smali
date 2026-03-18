.class public final Lgr/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public d:I

.field public e:Ljava/lang/String;

.field public final f:Ljava/lang/CharSequence;

.field public final g:Lgr/b;

.field public h:I

.field public i:I

.field public final synthetic j:Lgr/c;


# direct methods
.method public constructor <init>(Lbb/g0;Ljava/lang/CharSequence;Lgr/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lgr/l;->j:Lgr/c;

    .line 5
    .line 6
    const/4 p3, 0x2

    .line 7
    iput p3, p0, Lgr/l;->d:I

    .line 8
    .line 9
    const/4 p3, 0x0

    .line 10
    iput p3, p0, Lgr/l;->h:I

    .line 11
    .line 12
    iget-object p3, p1, Lbb/g0;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p3, Lgr/b;

    .line 15
    .line 16
    iput-object p3, p0, Lgr/l;->g:Lgr/b;

    .line 17
    .line 18
    iget p1, p1, Lbb/g0;->e:I

    .line 19
    .line 20
    iput p1, p0, Lgr/l;->i:I

    .line 21
    .line 22
    iput-object p2, p0, Lgr/l;->f:Ljava/lang/CharSequence;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 9

    .line 1
    iget v0, p0, Lgr/l;->d:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    if-eq v0, v1, :cond_c

    .line 5
    .line 6
    invoke-static {v0}, Lu/w;->o(I)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v0, :cond_b

    .line 12
    .line 13
    const/4 v3, 0x2

    .line 14
    if-eq v0, v3, :cond_a

    .line 15
    .line 16
    iput v1, p0, Lgr/l;->d:I

    .line 17
    .line 18
    iget v0, p0, Lgr/l;->h:I

    .line 19
    .line 20
    :cond_0
    :goto_0
    iget v1, p0, Lgr/l;->h:I

    .line 21
    .line 22
    const/4 v3, -0x1

    .line 23
    const/4 v4, 0x3

    .line 24
    if-eq v1, v3, :cond_9

    .line 25
    .line 26
    iget-object v5, p0, Lgr/l;->f:Ljava/lang/CharSequence;

    .line 27
    .line 28
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    invoke-static {v1, v6}, Lkp/i9;->f(II)V

    .line 33
    .line 34
    .line 35
    :goto_1
    if-ge v1, v6, :cond_2

    .line 36
    .line 37
    invoke-interface {v5, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result v7

    .line 41
    iget-object v8, p0, Lgr/l;->j:Lgr/c;

    .line 42
    .line 43
    invoke-virtual {v8, v7}, Lgr/c;->a(C)Z

    .line 44
    .line 45
    .line 46
    move-result v7

    .line 47
    if-eqz v7, :cond_1

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    move v1, v3

    .line 54
    :goto_2
    if-ne v1, v3, :cond_3

    .line 55
    .line 56
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    iput v3, p0, Lgr/l;->h:I

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    add-int/lit8 v6, v1, 0x1

    .line 64
    .line 65
    iput v6, p0, Lgr/l;->h:I

    .line 66
    .line 67
    :goto_3
    iget v6, p0, Lgr/l;->h:I

    .line 68
    .line 69
    if-ne v6, v0, :cond_4

    .line 70
    .line 71
    add-int/lit8 v6, v6, 0x1

    .line 72
    .line 73
    iput v6, p0, Lgr/l;->h:I

    .line 74
    .line 75
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-le v6, v1, :cond_0

    .line 80
    .line 81
    iput v3, p0, Lgr/l;->h:I

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_4
    :goto_4
    iget-object v6, p0, Lgr/l;->g:Lgr/b;

    .line 85
    .line 86
    if-ge v0, v1, :cond_5

    .line 87
    .line 88
    invoke-interface {v5, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v7

    .line 92
    invoke-virtual {v6, v7}, Lgr/b;->a(C)Z

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    if-eqz v7, :cond_5

    .line 97
    .line 98
    add-int/lit8 v0, v0, 0x1

    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_5
    :goto_5
    if-le v1, v0, :cond_6

    .line 102
    .line 103
    add-int/lit8 v7, v1, -0x1

    .line 104
    .line 105
    invoke-interface {v5, v7}, Ljava/lang/CharSequence;->charAt(I)C

    .line 106
    .line 107
    .line 108
    move-result v7

    .line 109
    invoke-virtual {v6, v7}, Lgr/b;->a(C)Z

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    if-eqz v7, :cond_6

    .line 114
    .line 115
    add-int/lit8 v1, v1, -0x1

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_6
    iget v7, p0, Lgr/l;->i:I

    .line 119
    .line 120
    if-ne v7, v2, :cond_7

    .line 121
    .line 122
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    iput v3, p0, Lgr/l;->h:I

    .line 127
    .line 128
    :goto_6
    if-le v1, v0, :cond_8

    .line 129
    .line 130
    add-int/lit8 v3, v1, -0x1

    .line 131
    .line 132
    invoke-interface {v5, v3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    invoke-virtual {v6, v3}, Lgr/b;->a(C)Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    if-eqz v3, :cond_8

    .line 141
    .line 142
    add-int/lit8 v1, v1, -0x1

    .line 143
    .line 144
    goto :goto_6

    .line 145
    :cond_7
    sub-int/2addr v7, v2

    .line 146
    iput v7, p0, Lgr/l;->i:I

    .line 147
    .line 148
    :cond_8
    invoke-interface {v5, v0, v1}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    invoke-interface {v0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    goto :goto_7

    .line 157
    :cond_9
    iput v4, p0, Lgr/l;->d:I

    .line 158
    .line 159
    const/4 v0, 0x0

    .line 160
    :goto_7
    iput-object v0, p0, Lgr/l;->e:Ljava/lang/String;

    .line 161
    .line 162
    iget v0, p0, Lgr/l;->d:I

    .line 163
    .line 164
    if-eq v0, v4, :cond_a

    .line 165
    .line 166
    iput v2, p0, Lgr/l;->d:I

    .line 167
    .line 168
    return v2

    .line 169
    :cond_a
    const/4 p0, 0x0

    .line 170
    return p0

    .line 171
    :cond_b
    return v2

    .line 172
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 173
    .line 174
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 175
    .line 176
    .line 177
    throw p0
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lgr/l;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x2

    .line 8
    iput v0, p0, Lgr/l;->d:I

    .line 9
    .line 10
    iget-object v0, p0, Lgr/l;->e:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    iput-object v1, p0, Lgr/l;->e:Ljava/lang/String;

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public final remove()V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
