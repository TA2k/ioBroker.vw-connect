.class public final Lw3/b;
.super Lh/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static f:Lw3/b;

.field public static g:Lw3/b;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/text/BreakIterator;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lw3/b;->d:I

    .line 2
    .line 3
    const/16 p1, 0x8

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lh/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final e(I)[I
    .locals 4

    .line 1
    iget v0, p0, Lw3/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v1, 0x0

    .line 15
    if-gtz v0, :cond_0

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-lt p1, v0, :cond_1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    if-gez p1, :cond_2

    .line 30
    .line 31
    const/4 p1, 0x0

    .line 32
    :cond_2
    invoke-virtual {p0, p1}, Lw3/b;->s(I)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/4 v2, -0x1

    .line 37
    const-string v3, "impl"

    .line 38
    .line 39
    if-nez v0, :cond_5

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lw3/b;->s(I)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eqz v0, :cond_3

    .line 46
    .line 47
    if-eqz p1, :cond_5

    .line 48
    .line 49
    add-int/lit8 v0, p1, -0x1

    .line 50
    .line 51
    invoke-virtual {p0, v0}, Lw3/b;->s(I)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_3

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_3
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 59
    .line 60
    if-eqz v0, :cond_4

    .line 61
    .line 62
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->following(I)I

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    if-ne p1, v2, :cond_2

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_4
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v1

    .line 73
    :cond_5
    :goto_0
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 74
    .line 75
    if-eqz v0, :cond_8

    .line 76
    .line 77
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->following(I)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eq v0, v2, :cond_7

    .line 82
    .line 83
    invoke-virtual {p0, v0}, Lw3/b;->r(I)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-nez v2, :cond_6

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_6
    invoke-virtual {p0, p1, v0}, Lh/w;->i(II)[I

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    :cond_7
    :goto_1
    return-object v1

    .line 95
    :cond_8
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw v1

    .line 99
    :pswitch_0
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    const/4 v1, 0x0

    .line 108
    if-gtz v0, :cond_9

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_9
    if-lt p1, v0, :cond_a

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_a
    if-gez p1, :cond_b

    .line 115
    .line 116
    const/4 p1, 0x0

    .line 117
    :cond_b
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 118
    .line 119
    const-string v2, "impl"

    .line 120
    .line 121
    if-eqz v0, :cond_10

    .line 122
    .line 123
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->isBoundary(I)Z

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    const/4 v3, -0x1

    .line 128
    if-nez v0, :cond_d

    .line 129
    .line 130
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 131
    .line 132
    if-eqz v0, :cond_c

    .line 133
    .line 134
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->following(I)I

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-ne p1, v3, :cond_b

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_c
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw v1

    .line 145
    :cond_d
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 146
    .line 147
    if-eqz v0, :cond_f

    .line 148
    .line 149
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->following(I)I

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    if-ne v0, v3, :cond_e

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_e
    invoke-virtual {p0, p1, v0}, Lh/w;->i(II)[I

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    :goto_2
    return-object v1

    .line 161
    :cond_f
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw v1

    .line 165
    :cond_10
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw v1

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final m(I)[I
    .locals 4

    .line 1
    iget v0, p0, Lw3/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v1, 0x0

    .line 15
    if-gtz v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    if-gtz p1, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    if-le p1, v0, :cond_2

    .line 22
    .line 23
    move p1, v0

    .line 24
    :cond_2
    const/4 v0, -0x1

    .line 25
    const-string v2, "impl"

    .line 26
    .line 27
    if-lez p1, :cond_4

    .line 28
    .line 29
    add-int/lit8 v3, p1, -0x1

    .line 30
    .line 31
    invoke-virtual {p0, v3}, Lw3/b;->s(I)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-nez v3, :cond_4

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lw3/b;->r(I)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-nez v3, :cond_4

    .line 42
    .line 43
    iget-object v3, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 44
    .line 45
    if-eqz v3, :cond_3

    .line 46
    .line 47
    invoke-virtual {v3, p1}, Ljava/text/BreakIterator;->preceding(I)I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-ne p1, v0, :cond_2

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v1

    .line 58
    :cond_4
    iget-object v3, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 59
    .line 60
    if-eqz v3, :cond_7

    .line 61
    .line 62
    invoke-virtual {v3, p1}, Ljava/text/BreakIterator;->preceding(I)I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eq v2, v0, :cond_6

    .line 67
    .line 68
    invoke-virtual {p0, v2}, Lw3/b;->s(I)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_6

    .line 73
    .line 74
    if-eqz v2, :cond_5

    .line 75
    .line 76
    add-int/lit8 v0, v2, -0x1

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Lw3/b;->s(I)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-nez v0, :cond_6

    .line 83
    .line 84
    :cond_5
    invoke-virtual {p0, v2, p1}, Lh/w;->i(II)[I

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    :cond_6
    :goto_0
    return-object v1

    .line 89
    :cond_7
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw v1

    .line 93
    :pswitch_0
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    const/4 v1, 0x0

    .line 102
    if-gtz v0, :cond_8

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_8
    if-gtz p1, :cond_9

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_9
    if-le p1, v0, :cond_a

    .line 109
    .line 110
    move p1, v0

    .line 111
    :cond_a
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 112
    .line 113
    const-string v2, "impl"

    .line 114
    .line 115
    if-eqz v0, :cond_f

    .line 116
    .line 117
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->isBoundary(I)Z

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    const/4 v3, -0x1

    .line 122
    if-nez v0, :cond_c

    .line 123
    .line 124
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 125
    .line 126
    if-eqz v0, :cond_b

    .line 127
    .line 128
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->preceding(I)I

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    if-ne p1, v3, :cond_a

    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_b
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw v1

    .line 139
    :cond_c
    iget-object v0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 140
    .line 141
    if-eqz v0, :cond_e

    .line 142
    .line 143
    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->preceding(I)I

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    if-ne v0, v3, :cond_d

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_d
    invoke-virtual {p0, v0, p1}, Lh/w;->i(II)[I

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    :goto_1
    return-object v1

    .line 155
    :cond_e
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw v1

    .line 159
    :cond_f
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw v1

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final q(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget v0, p0, Lw3/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/text/BreakIterator;->setText(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    const-string p0, "impl"

    .line 17
    .line 18
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    throw p0

    .line 23
    :pswitch_0
    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 24
    .line 25
    iget-object p0, p0, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 26
    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljava/text/BreakIterator;->setText(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    const-string p0, "impl"

    .line 34
    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    throw p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public r(I)Z
    .locals 1

    .line 1
    if-lez p1, :cond_1

    .line 2
    .line 3
    add-int/lit8 v0, p1, -0x1

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lw3/b;->s(I)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eq p1, v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lw3/b;->s(I)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-nez p0, :cond_1

    .line 26
    .line 27
    :cond_0
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_1
    const/4 p0, 0x0

    .line 30
    return p0
.end method

.method public s(I)Z
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-ge p1, v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lh/w;->j()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/String;->codePointAt(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    invoke-static {p0}, Ljava/lang/Character;->isLetterOrDigit(I)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0
.end method
