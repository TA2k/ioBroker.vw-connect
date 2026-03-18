.class public final synthetic Lv01/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lkotlin/jvm/internal/f0;

.field public final synthetic f:Lu01/b0;

.field public final synthetic g:Lkotlin/jvm/internal/f0;

.field public final synthetic h:Lkotlin/jvm/internal/f0;


# direct methods
.method public synthetic constructor <init>(Lkotlin/jvm/internal/f0;Lu01/b0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lv01/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lv01/j;->e:Lkotlin/jvm/internal/f0;

    iput-object p2, p0, Lv01/j;->f:Lu01/b0;

    iput-object p3, p0, Lv01/j;->g:Lkotlin/jvm/internal/f0;

    iput-object p4, p0, Lv01/j;->h:Lkotlin/jvm/internal/f0;

    return-void
.end method

.method public synthetic constructor <init>(Lu01/b0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lv01/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lv01/j;->f:Lu01/b0;

    iput-object p2, p0, Lv01/j;->e:Lkotlin/jvm/internal/f0;

    iput-object p3, p0, Lv01/j;->g:Lkotlin/jvm/internal/f0;

    iput-object p4, p0, Lv01/j;->h:Lkotlin/jvm/internal/f0;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lv01/j;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Integer;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    check-cast p2, Ljava/lang/Long;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    const/4 p2, 0x1

    .line 19
    if-ne p1, p2, :cond_2

    .line 20
    .line 21
    iget-object p1, p0, Lv01/j;->e:Lkotlin/jvm/internal/f0;

    .line 22
    .line 23
    iget-object p2, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 24
    .line 25
    if-nez p2, :cond_1

    .line 26
    .line 27
    const-wide/16 v2, 0x18

    .line 28
    .line 29
    cmp-long p2, v0, v2

    .line 30
    .line 31
    if-nez p2, :cond_0

    .line 32
    .line 33
    iget-object p2, p0, Lv01/j;->f:Lu01/b0;

    .line 34
    .line 35
    invoke-virtual {p2}, Lu01/b0;->f()J

    .line 36
    .line 37
    .line 38
    move-result-wide v0

    .line 39
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iput-object v0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 44
    .line 45
    invoke-virtual {p2}, Lu01/b0;->f()J

    .line 46
    .line 47
    .line 48
    move-result-wide v0

    .line 49
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    iget-object v0, p0, Lv01/j;->g:Lkotlin/jvm/internal/f0;

    .line 54
    .line 55
    iput-object p1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-virtual {p2}, Lu01/b0;->f()J

    .line 58
    .line 59
    .line 60
    move-result-wide p1

    .line 61
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    iget-object p0, p0, Lv01/j;->h:Lkotlin/jvm/internal/f0;

    .line 66
    .line 67
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 71
    .line 72
    const-string p1, "bad zip: NTFS extra attribute tag 0x0001 size != 24"

    .line 73
    .line 74
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 79
    .line 80
    const-string p1, "bad zip: NTFS extra attribute tag 0x0001 repeated"

    .line 81
    .line 82
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 90
    .line 91
    .line 92
    move-result-wide v0

    .line 93
    const/16 p2, 0x5455

    .line 94
    .line 95
    if-ne p1, p2, :cond_d

    .line 96
    .line 97
    const-wide/16 p1, 0x1

    .line 98
    .line 99
    cmp-long v2, v0, p1

    .line 100
    .line 101
    const-string v3, "bad zip: extended timestamp extra too short"

    .line 102
    .line 103
    if-ltz v2, :cond_c

    .line 104
    .line 105
    iget-object v2, p0, Lv01/j;->f:Lu01/b0;

    .line 106
    .line 107
    invoke-virtual {v2}, Lu01/b0;->readByte()B

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    and-int/lit8 v5, v4, 0x1

    .line 112
    .line 113
    const/4 v6, 0x0

    .line 114
    const/4 v7, 0x1

    .line 115
    if-ne v5, v7, :cond_3

    .line 116
    .line 117
    move v5, v7

    .line 118
    goto :goto_1

    .line 119
    :cond_3
    move v5, v6

    .line 120
    :goto_1
    and-int/lit8 v8, v4, 0x2

    .line 121
    .line 122
    const/4 v9, 0x2

    .line 123
    if-ne v8, v9, :cond_4

    .line 124
    .line 125
    move v8, v7

    .line 126
    goto :goto_2

    .line 127
    :cond_4
    move v8, v6

    .line 128
    :goto_2
    const/4 v9, 0x4

    .line 129
    and-int/2addr v4, v9

    .line 130
    if-ne v4, v9, :cond_5

    .line 131
    .line 132
    move v6, v7

    .line 133
    :cond_5
    if-eqz v5, :cond_6

    .line 134
    .line 135
    const-wide/16 p1, 0x5

    .line 136
    .line 137
    :cond_6
    const-wide/16 v9, 0x4

    .line 138
    .line 139
    if-eqz v8, :cond_7

    .line 140
    .line 141
    add-long/2addr p1, v9

    .line 142
    :cond_7
    if-eqz v6, :cond_8

    .line 143
    .line 144
    add-long/2addr p1, v9

    .line 145
    :cond_8
    cmp-long p1, v0, p1

    .line 146
    .line 147
    if-ltz p1, :cond_b

    .line 148
    .line 149
    if-eqz v5, :cond_9

    .line 150
    .line 151
    invoke-virtual {v2}, Lu01/b0;->d()I

    .line 152
    .line 153
    .line 154
    move-result p1

    .line 155
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    iget-object p2, p0, Lv01/j;->e:Lkotlin/jvm/internal/f0;

    .line 160
    .line 161
    iput-object p1, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 162
    .line 163
    :cond_9
    if-eqz v8, :cond_a

    .line 164
    .line 165
    invoke-virtual {v2}, Lu01/b0;->d()I

    .line 166
    .line 167
    .line 168
    move-result p1

    .line 169
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    iget-object p2, p0, Lv01/j;->g:Lkotlin/jvm/internal/f0;

    .line 174
    .line 175
    iput-object p1, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 176
    .line 177
    :cond_a
    if-eqz v6, :cond_d

    .line 178
    .line 179
    invoke-virtual {v2}, Lu01/b0;->d()I

    .line 180
    .line 181
    .line 182
    move-result p1

    .line 183
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 184
    .line 185
    .line 186
    move-result-object p1

    .line 187
    iget-object p0, p0, Lv01/j;->h:Lkotlin/jvm/internal/f0;

    .line 188
    .line 189
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 190
    .line 191
    goto :goto_3

    .line 192
    :cond_b
    new-instance p0, Ljava/io/IOException;

    .line 193
    .line 194
    invoke-direct {p0, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    throw p0

    .line 198
    :cond_c
    new-instance p0, Ljava/io/IOException;

    .line 199
    .line 200
    invoke-direct {p0, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0

    .line 204
    :cond_d
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 205
    .line 206
    return-object p0

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
