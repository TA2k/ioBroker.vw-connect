.class public abstract Lhr/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:I

.field public g:I

.field public final synthetic h:Ljava/util/AbstractMap;


# direct methods
.method public constructor <init>(Lhr/v;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lhr/t;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 12
    iget v0, p1, Lhr/v;->h:I

    .line 13
    iput v0, p0, Lhr/t;->e:I

    .line 14
    invoke-virtual {p1}, Lhr/v;->isEmpty()Z

    move-result p1

    const/4 v0, -0x1

    if-eqz p1, :cond_0

    move p1, v0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 15
    :goto_0
    iput p1, p0, Lhr/t;->f:I

    .line 16
    iput v0, p0, Lhr/t;->g:I

    return-void
.end method

.method public constructor <init>(Ljp/t;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lhr/t;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 2
    iget v0, p1, Ljp/t;->h:I

    .line 3
    iput v0, p0, Lhr/t;->e:I

    .line 4
    invoke-virtual {p1}, Ljp/t;->isEmpty()Z

    move-result p1

    const/4 v0, -0x1

    if-eqz p1, :cond_0

    move p1, v0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 5
    :goto_0
    iput p1, p0, Lhr/t;->f:I

    iput v0, p0, Lhr/t;->g:I

    return-void
.end method

.method public constructor <init>(Llp/j;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lhr/t;->d:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 7
    iget v0, p1, Llp/j;->h:I

    .line 8
    iput v0, p0, Lhr/t;->e:I

    .line 9
    invoke-virtual {p1}, Llp/j;->isEmpty()Z

    move-result p1

    const/4 v0, -0x1

    if-eqz p1, :cond_0

    move p1, v0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 10
    :goto_0
    iput p1, p0, Lhr/t;->f:I

    iput v0, p0, Lhr/t;->g:I

    return-void
.end method


# virtual methods
.method public abstract a(I)Ljava/lang/Object;
.end method

.method public abstract b(I)Ljava/lang/Object;
.end method

.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lhr/t;->f:I

    .line 7
    .line 8
    if-ltz p0, :cond_0

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
    iget p0, p0, Lhr/t;->f:I

    .line 15
    .line 16
    if-ltz p0, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    :goto_1
    return p0

    .line 22
    :pswitch_1
    iget p0, p0, Lhr/t;->f:I

    .line 23
    .line 24
    if-ltz p0, :cond_2

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    goto :goto_2

    .line 28
    :cond_2
    const/4 p0, 0x0

    .line 29
    :goto_2
    return p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lhr/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 7
    .line 8
    check-cast v0, Llp/j;

    .line 9
    .line 10
    iget v1, v0, Llp/j;->h:I

    .line 11
    .line 12
    iget v2, p0, Lhr/t;->e:I

    .line 13
    .line 14
    if-ne v1, v2, :cond_2

    .line 15
    .line 16
    invoke-virtual {p0}, Lhr/t;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget v1, p0, Lhr/t;->f:I

    .line 23
    .line 24
    iput v1, p0, Lhr/t;->g:I

    .line 25
    .line 26
    invoke-virtual {p0, v1}, Lhr/t;->b(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget v2, p0, Lhr/t;->f:I

    .line 31
    .line 32
    add-int/lit8 v2, v2, 0x1

    .line 33
    .line 34
    iget v0, v0, Llp/j;->i:I

    .line 35
    .line 36
    if-ge v2, v0, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v2, -0x1

    .line 40
    :goto_0
    iput v2, p0, Lhr/t;->f:I

    .line 41
    .line 42
    return-object v1

    .line 43
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 44
    .line 45
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 50
    .line 51
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :pswitch_0
    iget-object v0, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 56
    .line 57
    check-cast v0, Ljp/t;

    .line 58
    .line 59
    iget v1, v0, Ljp/t;->h:I

    .line 60
    .line 61
    iget v2, p0, Lhr/t;->e:I

    .line 62
    .line 63
    if-ne v1, v2, :cond_5

    .line 64
    .line 65
    invoke-virtual {p0}, Lhr/t;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_4

    .line 70
    .line 71
    iget v1, p0, Lhr/t;->f:I

    .line 72
    .line 73
    iput v1, p0, Lhr/t;->g:I

    .line 74
    .line 75
    invoke-virtual {p0, v1}, Lhr/t;->b(I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    iget v2, p0, Lhr/t;->f:I

    .line 80
    .line 81
    add-int/lit8 v2, v2, 0x1

    .line 82
    .line 83
    iget v0, v0, Ljp/t;->i:I

    .line 84
    .line 85
    if-ge v2, v0, :cond_3

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_3
    const/4 v2, -0x1

    .line 89
    :goto_1
    iput v2, p0, Lhr/t;->f:I

    .line 90
    .line 91
    return-object v1

    .line 92
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 93
    .line 94
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_5
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :pswitch_1
    iget-object v0, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 105
    .line 106
    check-cast v0, Lhr/v;

    .line 107
    .line 108
    iget v1, v0, Lhr/v;->h:I

    .line 109
    .line 110
    iget v2, p0, Lhr/t;->e:I

    .line 111
    .line 112
    if-ne v1, v2, :cond_8

    .line 113
    .line 114
    invoke-virtual {p0}, Lhr/t;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result v1

    .line 118
    if-eqz v1, :cond_7

    .line 119
    .line 120
    iget v1, p0, Lhr/t;->f:I

    .line 121
    .line 122
    iput v1, p0, Lhr/t;->g:I

    .line 123
    .line 124
    invoke-virtual {p0, v1}, Lhr/t;->a(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    iget v2, p0, Lhr/t;->f:I

    .line 129
    .line 130
    add-int/lit8 v2, v2, 0x1

    .line 131
    .line 132
    iget v0, v0, Lhr/v;->i:I

    .line 133
    .line 134
    if-ge v2, v0, :cond_6

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_6
    const/4 v2, -0x1

    .line 138
    :goto_2
    iput v2, p0, Lhr/t;->f:I

    .line 139
    .line 140
    return-object v1

    .line 141
    :cond_7
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 142
    .line 143
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 144
    .line 145
    .line 146
    throw p0

    .line 147
    :cond_8
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 148
    .line 149
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 150
    .line 151
    .line 152
    throw p0

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 4

    .line 1
    iget v0, p0, Lhr/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 7
    .line 8
    check-cast v0, Llp/j;

    .line 9
    .line 10
    iget v1, v0, Llp/j;->h:I

    .line 11
    .line 12
    iget v2, p0, Lhr/t;->e:I

    .line 13
    .line 14
    if-ne v1, v2, :cond_2

    .line 15
    .line 16
    iget v1, p0, Lhr/t;->g:I

    .line 17
    .line 18
    if-ltz v1, :cond_0

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v3, 0x0

    .line 23
    :goto_0
    if-eqz v3, :cond_1

    .line 24
    .line 25
    add-int/lit8 v2, v2, 0x20

    .line 26
    .line 27
    iput v2, p0, Lhr/t;->e:I

    .line 28
    .line 29
    invoke-virtual {v0}, Llp/j;->b()[Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    aget-object v1, v2, v1

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Llp/j;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    iget v0, p0, Lhr/t;->f:I

    .line 39
    .line 40
    const/4 v1, -0x1

    .line 41
    add-int/2addr v0, v1

    .line 42
    iput v0, p0, Lhr/t;->f:I

    .line 43
    .line 44
    iput v1, p0, Lhr/t;->g:I

    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string v0, "no calls to next() since the last call to remove()"

    .line 50
    .line 51
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :pswitch_0
    iget-object v0, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 62
    .line 63
    check-cast v0, Ljp/t;

    .line 64
    .line 65
    iget v1, v0, Ljp/t;->h:I

    .line 66
    .line 67
    iget v2, p0, Lhr/t;->e:I

    .line 68
    .line 69
    if-ne v1, v2, :cond_4

    .line 70
    .line 71
    iget v1, p0, Lhr/t;->g:I

    .line 72
    .line 73
    if-ltz v1, :cond_3

    .line 74
    .line 75
    const/4 v1, 0x1

    .line 76
    goto :goto_1

    .line 77
    :cond_3
    const/4 v1, 0x0

    .line 78
    :goto_1
    const-string v2, "no calls to next() since the last call to remove()"

    .line 79
    .line 80
    invoke-static {v2, v1}, Llp/ic;->d(Ljava/lang/String;Z)V

    .line 81
    .line 82
    .line 83
    iget v1, p0, Lhr/t;->e:I

    .line 84
    .line 85
    add-int/lit8 v1, v1, 0x20

    .line 86
    .line 87
    iput v1, p0, Lhr/t;->e:I

    .line 88
    .line 89
    iget v1, p0, Lhr/t;->g:I

    .line 90
    .line 91
    invoke-virtual {v0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    aget-object v1, v2, v1

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljp/t;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    iget v0, p0, Lhr/t;->f:I

    .line 101
    .line 102
    const/4 v1, -0x1

    .line 103
    add-int/2addr v0, v1

    .line 104
    iput v0, p0, Lhr/t;->f:I

    .line 105
    .line 106
    iput v1, p0, Lhr/t;->g:I

    .line 107
    .line 108
    return-void

    .line 109
    :cond_4
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 110
    .line 111
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :pswitch_1
    iget-object v0, p0, Lhr/t;->h:Ljava/util/AbstractMap;

    .line 116
    .line 117
    check-cast v0, Lhr/v;

    .line 118
    .line 119
    iget v1, v0, Lhr/v;->h:I

    .line 120
    .line 121
    iget v2, p0, Lhr/t;->e:I

    .line 122
    .line 123
    if-ne v1, v2, :cond_6

    .line 124
    .line 125
    iget v1, p0, Lhr/t;->g:I

    .line 126
    .line 127
    const/4 v2, 0x1

    .line 128
    if-ltz v1, :cond_5

    .line 129
    .line 130
    move v1, v2

    .line 131
    goto :goto_2

    .line 132
    :cond_5
    const/4 v1, 0x0

    .line 133
    :goto_2
    const-string v3, "no calls to next() since the last call to remove()"

    .line 134
    .line 135
    invoke-static {v3, v1}, Lkp/i9;->h(Ljava/lang/String;Z)V

    .line 136
    .line 137
    .line 138
    iget v1, p0, Lhr/t;->e:I

    .line 139
    .line 140
    add-int/lit8 v1, v1, 0x20

    .line 141
    .line 142
    iput v1, p0, Lhr/t;->e:I

    .line 143
    .line 144
    iget v1, p0, Lhr/t;->g:I

    .line 145
    .line 146
    invoke-virtual {v0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    aget-object v1, v3, v1

    .line 151
    .line 152
    invoke-virtual {v0, v1}, Lhr/v;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    iget v0, p0, Lhr/t;->f:I

    .line 156
    .line 157
    sub-int/2addr v0, v2

    .line 158
    iput v0, p0, Lhr/t;->f:I

    .line 159
    .line 160
    const/4 v0, -0x1

    .line 161
    iput v0, p0, Lhr/t;->g:I

    .line 162
    .line 163
    return-void

    .line 164
    :cond_6
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 165
    .line 166
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 167
    .line 168
    .line 169
    throw p0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
