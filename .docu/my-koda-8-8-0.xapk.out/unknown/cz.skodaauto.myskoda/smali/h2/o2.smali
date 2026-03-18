.class public final synthetic Lh2/o2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/io/Serializable;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Long;JLay0/k;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;I)V
    .locals 0

    .line 1
    const/4 p11, 0x0

    iput p11, p0, Lh2/o2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/o2;->f:Ljava/io/Serializable;

    iput-wide p2, p0, Lh2/o2;->e:J

    iput-object p4, p0, Lh2/o2;->g:Ljava/lang/Object;

    iput-object p5, p0, Lh2/o2;->h:Ljava/lang/Object;

    iput-object p6, p0, Lh2/o2;->i:Ljava/lang/Object;

    iput-object p7, p0, Lh2/o2;->j:Ljava/lang/Object;

    iput-object p8, p0, Lh2/o2;->k:Ljava/lang/Object;

    iput-object p9, p0, Lh2/o2;->l:Ljava/lang/Object;

    iput-object p10, p0, Lh2/o2;->m:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/b0;JLkotlin/jvm/internal/e0;Lu01/b0;Lkotlin/jvm/internal/e0;Lkotlin/jvm/internal/e0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lh2/o2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/o2;->f:Ljava/io/Serializable;

    iput-wide p2, p0, Lh2/o2;->e:J

    iput-object p4, p0, Lh2/o2;->g:Ljava/lang/Object;

    iput-object p5, p0, Lh2/o2;->h:Ljava/lang/Object;

    iput-object p6, p0, Lh2/o2;->i:Ljava/lang/Object;

    iput-object p7, p0, Lh2/o2;->j:Ljava/lang/Object;

    iput-object p8, p0, Lh2/o2;->k:Ljava/lang/Object;

    iput-object p9, p0, Lh2/o2;->l:Ljava/lang/Object;

    iput-object p10, p0, Lh2/o2;->m:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lh2/o2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/o2;->f:Ljava/io/Serializable;

    .line 7
    .line 8
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 9
    .line 10
    iget-object v1, p0, Lh2/o2;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lkotlin/jvm/internal/e0;

    .line 13
    .line 14
    iget-object v2, p0, Lh2/o2;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lu01/b0;

    .line 17
    .line 18
    iget-object v3, p0, Lh2/o2;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Lkotlin/jvm/internal/e0;

    .line 21
    .line 22
    iget-object v4, p0, Lh2/o2;->j:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v4, Lkotlin/jvm/internal/e0;

    .line 25
    .line 26
    iget-object v5, p0, Lh2/o2;->k:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v5, Lkotlin/jvm/internal/f0;

    .line 29
    .line 30
    iget-object v6, p0, Lh2/o2;->l:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v6, Lkotlin/jvm/internal/f0;

    .line 33
    .line 34
    iget-object v7, p0, Lh2/o2;->m:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v7, Lkotlin/jvm/internal/f0;

    .line 37
    .line 38
    check-cast p1, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    check-cast p2, Ljava/lang/Long;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 47
    .line 48
    .line 49
    move-result-wide v8

    .line 50
    const/4 p2, 0x1

    .line 51
    if-eq p1, p2, :cond_2

    .line 52
    .line 53
    const/16 p0, 0xa

    .line 54
    .line 55
    if-eq p1, p0, :cond_0

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_0
    const-wide/16 p0, 0x4

    .line 59
    .line 60
    cmp-long p2, v8, p0

    .line 61
    .line 62
    if-ltz p2, :cond_1

    .line 63
    .line 64
    invoke-virtual {v2, p0, p1}, Lu01/b0;->skip(J)V

    .line 65
    .line 66
    .line 67
    sub-long/2addr v8, p0

    .line 68
    long-to-int p0, v8

    .line 69
    new-instance p1, Lv01/j;

    .line 70
    .line 71
    invoke-direct {p1, v5, v2, v6, v7}, Lv01/j;-><init>(Lkotlin/jvm/internal/f0;Lu01/b0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V

    .line 72
    .line 73
    .line 74
    invoke-static {v2, p0, p1}, Lv01/b;->g(Lu01/b0;ILay0/n;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 79
    .line 80
    const-string p1, "bad zip: NTFS extra too short"

    .line 81
    .line 82
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_2
    iget-boolean p1, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 87
    .line 88
    if-nez p1, :cond_7

    .line 89
    .line 90
    iput-boolean p2, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 91
    .line 92
    iget-wide p0, p0, Lh2/o2;->e:J

    .line 93
    .line 94
    cmp-long p0, v8, p0

    .line 95
    .line 96
    if-ltz p0, :cond_6

    .line 97
    .line 98
    iget-wide p0, v1, Lkotlin/jvm/internal/e0;->d:J

    .line 99
    .line 100
    const-wide v5, 0xffffffffL

    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    cmp-long p2, p0, v5

    .line 106
    .line 107
    if-nez p2, :cond_3

    .line 108
    .line 109
    invoke-virtual {v2}, Lu01/b0;->f()J

    .line 110
    .line 111
    .line 112
    move-result-wide p0

    .line 113
    :cond_3
    iput-wide p0, v1, Lkotlin/jvm/internal/e0;->d:J

    .line 114
    .line 115
    iget-wide p0, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 116
    .line 117
    cmp-long p0, p0, v5

    .line 118
    .line 119
    const-wide/16 p1, 0x0

    .line 120
    .line 121
    if-nez p0, :cond_4

    .line 122
    .line 123
    invoke-virtual {v2}, Lu01/b0;->f()J

    .line 124
    .line 125
    .line 126
    move-result-wide v0

    .line 127
    goto :goto_0

    .line 128
    :cond_4
    move-wide v0, p1

    .line 129
    :goto_0
    iput-wide v0, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 130
    .line 131
    iget-wide v0, v4, Lkotlin/jvm/internal/e0;->d:J

    .line 132
    .line 133
    cmp-long p0, v0, v5

    .line 134
    .line 135
    if-nez p0, :cond_5

    .line 136
    .line 137
    invoke-virtual {v2}, Lu01/b0;->f()J

    .line 138
    .line 139
    .line 140
    move-result-wide p1

    .line 141
    :cond_5
    iput-wide p1, v4, Lkotlin/jvm/internal/e0;->d:J

    .line 142
    .line 143
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_6
    new-instance p0, Ljava/io/IOException;

    .line 147
    .line 148
    const-string p1, "bad zip: zip64 extra too short"

    .line 149
    .line 150
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0

    .line 154
    :cond_7
    new-instance p0, Ljava/io/IOException;

    .line 155
    .line 156
    const-string p1, "bad zip: zip64 extra repeated"

    .line 157
    .line 158
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :pswitch_0
    iget-object v0, p0, Lh2/o2;->f:Ljava/io/Serializable;

    .line 163
    .line 164
    move-object v1, v0

    .line 165
    check-cast v1, Ljava/lang/Long;

    .line 166
    .line 167
    iget-object v0, p0, Lh2/o2;->g:Ljava/lang/Object;

    .line 168
    .line 169
    move-object v4, v0

    .line 170
    check-cast v4, Lay0/k;

    .line 171
    .line 172
    iget-object v0, p0, Lh2/o2;->h:Ljava/lang/Object;

    .line 173
    .line 174
    move-object v5, v0

    .line 175
    check-cast v5, Lay0/k;

    .line 176
    .line 177
    iget-object v0, p0, Lh2/o2;->i:Ljava/lang/Object;

    .line 178
    .line 179
    move-object v6, v0

    .line 180
    check-cast v6, Li2/z;

    .line 181
    .line 182
    iget-object v0, p0, Lh2/o2;->j:Ljava/lang/Object;

    .line 183
    .line 184
    move-object v7, v0

    .line 185
    check-cast v7, Lgy0/j;

    .line 186
    .line 187
    iget-object v0, p0, Lh2/o2;->k:Ljava/lang/Object;

    .line 188
    .line 189
    move-object v8, v0

    .line 190
    check-cast v8, Lh2/g2;

    .line 191
    .line 192
    iget-object v0, p0, Lh2/o2;->l:Ljava/lang/Object;

    .line 193
    .line 194
    move-object v9, v0

    .line 195
    check-cast v9, Lh2/e8;

    .line 196
    .line 197
    iget-object v0, p0, Lh2/o2;->m:Ljava/lang/Object;

    .line 198
    .line 199
    move-object v10, v0

    .line 200
    check-cast v10, Lh2/z1;

    .line 201
    .line 202
    move-object v11, p1

    .line 203
    check-cast v11, Ll2/o;

    .line 204
    .line 205
    check-cast p2, Ljava/lang/Integer;

    .line 206
    .line 207
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 208
    .line 209
    .line 210
    const/4 p1, 0x1

    .line 211
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 212
    .line 213
    .line 214
    move-result v12

    .line 215
    iget-wide v2, p0, Lh2/o2;->e:J

    .line 216
    .line 217
    invoke-static/range {v1 .. v12}, Lh2/m3;->c(Ljava/lang/Long;JLay0/k;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Ll2/o;I)V

    .line 218
    .line 219
    .line 220
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 221
    .line 222
    return-object p0

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
