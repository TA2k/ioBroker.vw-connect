.class public Landroidx/collection/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/collection/d1;->d:I

    iput-object p1, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Luz0/x;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Landroidx/collection/d1;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 5
    iget p1, p1, Luz0/d1;->c:I

    .line 6
    iput p1, p0, Landroidx/collection/d1;->e:I

    return-void
.end method

.method public constructor <init>([Ljava/lang/Object;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Landroidx/collection/d1;->d:I

    const-string v0, "array"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/d1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Landroidx/collection/d1;->e:I

    .line 7
    .line 8
    if-lez p0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    return p0

    .line 14
    :pswitch_0
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 15
    .line 16
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lmx0/e;

    .line 19
    .line 20
    invoke-virtual {p0}, Lmx0/a;->c()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-ge v0, p0, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    :goto_1
    return p0

    .line 30
    :pswitch_1
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 31
    .line 32
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, [S

    .line 35
    .line 36
    array-length p0, p0

    .line 37
    if-ge v0, p0, :cond_2

    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/4 p0, 0x0

    .line 42
    :goto_2
    return p0

    .line 43
    :pswitch_2
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 44
    .line 45
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, [J

    .line 48
    .line 49
    array-length p0, p0

    .line 50
    if-ge v0, p0, :cond_3

    .line 51
    .line 52
    const/4 p0, 0x1

    .line 53
    goto :goto_3

    .line 54
    :cond_3
    const/4 p0, 0x0

    .line 55
    :goto_3
    return p0

    .line 56
    :pswitch_3
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 57
    .line 58
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p0, [I

    .line 61
    .line 62
    array-length p0, p0

    .line 63
    if-ge v0, p0, :cond_4

    .line 64
    .line 65
    const/4 p0, 0x1

    .line 66
    goto :goto_4

    .line 67
    :cond_4
    const/4 p0, 0x0

    .line 68
    :goto_4
    return p0

    .line 69
    :pswitch_4
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 70
    .line 71
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, [Ljava/lang/Object;

    .line 74
    .line 75
    array-length p0, p0

    .line 76
    if-ge v0, p0, :cond_5

    .line 77
    .line 78
    const/4 p0, 0x1

    .line 79
    goto :goto_5

    .line 80
    :cond_5
    const/4 p0, 0x0

    .line 81
    :goto_5
    return p0

    .line 82
    :pswitch_5
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 83
    .line 84
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p0, Landroid/view/ViewGroup;

    .line 87
    .line 88
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    if-ge v0, p0, :cond_6

    .line 93
    .line 94
    const/4 p0, 0x1

    .line 95
    goto :goto_6

    .line 96
    :cond_6
    const/4 p0, 0x0

    .line 97
    :goto_6
    return p0

    .line 98
    :pswitch_6
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 99
    .line 100
    iget-object p0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Landroidx/collection/b1;

    .line 103
    .line 104
    invoke-virtual {p0}, Landroidx/collection/b1;->f()I

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    if-ge v0, p0, :cond_7

    .line 109
    .line 110
    const/4 p0, 0x1

    .line 111
    goto :goto_7

    .line 112
    :cond_7
    const/4 p0, 0x0

    .line 113
    :goto_7
    return p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Landroidx/collection/d1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luz0/x;

    .line 9
    .line 10
    iget v1, v0, Luz0/d1;->c:I

    .line 11
    .line 12
    iget v2, p0, Landroidx/collection/d1;->e:I

    .line 13
    .line 14
    add-int/lit8 v3, v2, -0x1

    .line 15
    .line 16
    iput v3, p0, Landroidx/collection/d1;->e:I

    .line 17
    .line 18
    sub-int/2addr v1, v2

    .line 19
    iget-object p0, v0, Luz0/d1;->e:[Ljava/lang/String;

    .line 20
    .line 21
    aget-object p0, p0, v1

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    invoke-virtual {p0}, Landroidx/collection/d1;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    iget-object v0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lmx0/e;

    .line 33
    .line 34
    iget v1, p0, Landroidx/collection/d1;->e:I

    .line 35
    .line 36
    add-int/lit8 v2, v1, 0x1

    .line 37
    .line 38
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 39
    .line 40
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :pswitch_1
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 52
    .line 53
    iget-object v1, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v1, [S

    .line 56
    .line 57
    array-length v2, v1

    .line 58
    if-ge v0, v2, :cond_1

    .line 59
    .line 60
    add-int/lit8 v2, v0, 0x1

    .line 61
    .line 62
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 63
    .line 64
    aget-short p0, v1, v0

    .line 65
    .line 66
    new-instance v0, Llx0/z;

    .line 67
    .line 68
    invoke-direct {v0, p0}, Llx0/z;-><init>(S)V

    .line 69
    .line 70
    .line 71
    return-object v0

    .line 72
    :cond_1
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 73
    .line 74
    iget p0, p0, Landroidx/collection/d1;->e:I

    .line 75
    .line 76
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-direct {v0, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw v0

    .line 84
    :pswitch_2
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 85
    .line 86
    iget-object v1, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v1, [J

    .line 89
    .line 90
    array-length v2, v1

    .line 91
    if-ge v0, v2, :cond_2

    .line 92
    .line 93
    add-int/lit8 v2, v0, 0x1

    .line 94
    .line 95
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 96
    .line 97
    aget-wide v0, v1, v0

    .line 98
    .line 99
    new-instance p0, Llx0/w;

    .line 100
    .line 101
    invoke-direct {p0, v0, v1}, Llx0/w;-><init>(J)V

    .line 102
    .line 103
    .line 104
    return-object p0

    .line 105
    :cond_2
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 106
    .line 107
    iget p0, p0, Landroidx/collection/d1;->e:I

    .line 108
    .line 109
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-direct {v0, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw v0

    .line 117
    :pswitch_3
    iget v0, p0, Landroidx/collection/d1;->e:I

    .line 118
    .line 119
    iget-object v1, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v1, [I

    .line 122
    .line 123
    array-length v2, v1

    .line 124
    if-ge v0, v2, :cond_3

    .line 125
    .line 126
    add-int/lit8 v2, v0, 0x1

    .line 127
    .line 128
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 129
    .line 130
    aget p0, v1, v0

    .line 131
    .line 132
    new-instance v0, Llx0/u;

    .line 133
    .line 134
    invoke-direct {v0, p0}, Llx0/u;-><init>(I)V

    .line 135
    .line 136
    .line 137
    return-object v0

    .line 138
    :cond_3
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 139
    .line 140
    iget p0, p0, Landroidx/collection/d1;->e:I

    .line 141
    .line 142
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-direct {v0, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    throw v0

    .line 150
    :pswitch_4
    :try_start_0
    iget-object v0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v0, [Ljava/lang/Object;

    .line 153
    .line 154
    iget v1, p0, Landroidx/collection/d1;->e:I

    .line 155
    .line 156
    add-int/lit8 v2, v1, 0x1

    .line 157
    .line 158
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 159
    .line 160
    aget-object p0, v0, v1
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 161
    .line 162
    return-object p0

    .line 163
    :catch_0
    move-exception v0

    .line 164
    iget v1, p0, Landroidx/collection/d1;->e:I

    .line 165
    .line 166
    add-int/lit8 v1, v1, -0x1

    .line 167
    .line 168
    iput v1, p0, Landroidx/collection/d1;->e:I

    .line 169
    .line 170
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 171
    .line 172
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :pswitch_5
    iget-object v0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v0, Landroid/view/ViewGroup;

    .line 183
    .line 184
    iget v1, p0, Landroidx/collection/d1;->e:I

    .line 185
    .line 186
    add-int/lit8 v2, v1, 0x1

    .line 187
    .line 188
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 189
    .line 190
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    if-eqz p0, :cond_4

    .line 195
    .line 196
    return-object p0

    .line 197
    :cond_4
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 198
    .line 199
    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    .line 200
    .line 201
    .line 202
    throw p0

    .line 203
    :pswitch_6
    iget-object v0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Landroidx/collection/b1;

    .line 206
    .line 207
    iget v1, p0, Landroidx/collection/d1;->e:I

    .line 208
    .line 209
    add-int/lit8 v2, v1, 0x1

    .line 210
    .line 211
    iput v2, p0, Landroidx/collection/d1;->e:I

    .line 212
    .line 213
    invoke-virtual {v0, v1}, Landroidx/collection/b1;->h(I)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    return-object p0

    .line 218
    nop

    .line 219
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/d1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    const-string v0, "Operation is not supported for read-only collection"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    const-string v0, "Operation is not supported for read-only collection"

    .line 17
    .line 18
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :pswitch_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 23
    .line 24
    const-string v0, "Operation is not supported for read-only collection"

    .line 25
    .line 26
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :pswitch_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 31
    .line 32
    const-string v0, "Operation is not supported for read-only collection"

    .line 33
    .line 34
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :pswitch_3
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 39
    .line 40
    const-string v0, "Operation is not supported for read-only collection"

    .line 41
    .line 42
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :pswitch_4
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 47
    .line 48
    const-string v0, "Operation is not supported for read-only collection"

    .line 49
    .line 50
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :pswitch_5
    iget-object v0, p0, Landroidx/collection/d1;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Landroid/view/ViewGroup;

    .line 57
    .line 58
    iget v1, p0, Landroidx/collection/d1;->e:I

    .line 59
    .line 60
    add-int/lit8 v1, v1, -0x1

    .line 61
    .line 62
    iput v1, p0, Landroidx/collection/d1;->e:I

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->removeViewAt(I)V

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :pswitch_6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 69
    .line 70
    const-string v0, "Operation is not supported for read-only collection"

    .line 71
    .line 72
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
