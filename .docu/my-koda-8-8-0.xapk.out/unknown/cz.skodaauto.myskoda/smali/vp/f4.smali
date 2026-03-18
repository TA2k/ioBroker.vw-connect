.class public final Lvp/f4;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lvp/f4;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final A:I

.field public final B:Ljava/lang/String;

.field public final C:I

.field public final D:J

.field public final E:Ljava/lang/String;

.field public final F:Ljava/lang/String;

.field public final G:J

.field public final H:I

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:J

.field public final i:J

.field public final j:Ljava/lang/String;

.field public final k:Z

.field public final l:Z

.field public final m:J

.field public final n:Ljava/lang/String;

.field public final o:J

.field public final p:I

.field public final q:Z

.field public final r:Z

.field public final s:Ljava/lang/Boolean;

.field public final t:J

.field public final u:Ljava/util/List;

.field public final v:Ljava/lang/String;

.field public final w:Ljava/lang/String;

.field public final x:Ljava/lang/String;

.field public final y:Z

.field public final z:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltt/f;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltt/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;JJLjava/lang/String;ZZLjava/lang/String;JIZZLjava/lang/Boolean;JLjava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJILjava/lang/String;IJLjava/lang/String;Ljava/lang/String;JI)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    iput-object p1, p0, Lvp/f4;->d:Ljava/lang/String;

    const/4 p1, 0x1

    .line 3
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-ne p1, v0, :cond_0

    const/4 p2, 0x0

    :cond_0
    iput-object p2, p0, Lvp/f4;->e:Ljava/lang/String;

    iput-object p3, p0, Lvp/f4;->f:Ljava/lang/String;

    iput-wide p4, p0, Lvp/f4;->m:J

    iput-object p6, p0, Lvp/f4;->g:Ljava/lang/String;

    iput-wide p7, p0, Lvp/f4;->h:J

    iput-wide p9, p0, Lvp/f4;->i:J

    iput-object p11, p0, Lvp/f4;->j:Ljava/lang/String;

    iput-boolean p12, p0, Lvp/f4;->k:Z

    iput-boolean p13, p0, Lvp/f4;->l:Z

    iput-object p14, p0, Lvp/f4;->n:Ljava/lang/String;

    move-wide/from16 p1, p15

    iput-wide p1, p0, Lvp/f4;->o:J

    move/from16 p1, p17

    iput p1, p0, Lvp/f4;->p:I

    move/from16 p1, p18

    iput-boolean p1, p0, Lvp/f4;->q:Z

    move/from16 p1, p19

    iput-boolean p1, p0, Lvp/f4;->r:Z

    move-object/from16 p1, p20

    iput-object p1, p0, Lvp/f4;->s:Ljava/lang/Boolean;

    move-wide/from16 p1, p21

    iput-wide p1, p0, Lvp/f4;->t:J

    move-object/from16 p1, p23

    iput-object p1, p0, Lvp/f4;->u:Ljava/util/List;

    move-object/from16 p1, p24

    iput-object p1, p0, Lvp/f4;->v:Ljava/lang/String;

    move-object/from16 p1, p25

    iput-object p1, p0, Lvp/f4;->w:Ljava/lang/String;

    move-object/from16 p1, p26

    iput-object p1, p0, Lvp/f4;->x:Ljava/lang/String;

    move/from16 p1, p27

    iput-boolean p1, p0, Lvp/f4;->y:Z

    move-wide/from16 p1, p28

    iput-wide p1, p0, Lvp/f4;->z:J

    move/from16 p1, p30

    iput p1, p0, Lvp/f4;->A:I

    move-object/from16 p1, p31

    iput-object p1, p0, Lvp/f4;->B:Ljava/lang/String;

    move/from16 p1, p32

    iput p1, p0, Lvp/f4;->C:I

    move-wide/from16 p1, p33

    iput-wide p1, p0, Lvp/f4;->D:J

    move-object/from16 p1, p35

    iput-object p1, p0, Lvp/f4;->E:Ljava/lang/String;

    move-object/from16 p1, p36

    iput-object p1, p0, Lvp/f4;->F:Ljava/lang/String;

    move-wide/from16 p1, p37

    iput-wide p1, p0, Lvp/f4;->G:J

    move/from16 p1, p39

    iput p1, p0, Lvp/f4;->H:I

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJLjava/lang/String;ZZJLjava/lang/String;JIZZLjava/lang/Boolean;JLjava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJILjava/lang/String;IJLjava/lang/String;Ljava/lang/String;JI)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lvp/f4;->d:Ljava/lang/String;

    iput-object p2, p0, Lvp/f4;->e:Ljava/lang/String;

    iput-object p3, p0, Lvp/f4;->f:Ljava/lang/String;

    iput-wide p12, p0, Lvp/f4;->m:J

    iput-object p4, p0, Lvp/f4;->g:Ljava/lang/String;

    iput-wide p5, p0, Lvp/f4;->h:J

    iput-wide p7, p0, Lvp/f4;->i:J

    iput-object p9, p0, Lvp/f4;->j:Ljava/lang/String;

    iput-boolean p10, p0, Lvp/f4;->k:Z

    iput-boolean p11, p0, Lvp/f4;->l:Z

    iput-object p14, p0, Lvp/f4;->n:Ljava/lang/String;

    move-wide p1, p15

    iput-wide p1, p0, Lvp/f4;->o:J

    move/from16 p1, p17

    iput p1, p0, Lvp/f4;->p:I

    move/from16 p1, p18

    iput-boolean p1, p0, Lvp/f4;->q:Z

    move/from16 p1, p19

    iput-boolean p1, p0, Lvp/f4;->r:Z

    move-object/from16 p1, p20

    iput-object p1, p0, Lvp/f4;->s:Ljava/lang/Boolean;

    move-wide/from16 p1, p21

    iput-wide p1, p0, Lvp/f4;->t:J

    move-object/from16 p1, p23

    iput-object p1, p0, Lvp/f4;->u:Ljava/util/List;

    move-object/from16 p1, p24

    iput-object p1, p0, Lvp/f4;->v:Ljava/lang/String;

    move-object/from16 p1, p25

    iput-object p1, p0, Lvp/f4;->w:Ljava/lang/String;

    move-object/from16 p1, p26

    iput-object p1, p0, Lvp/f4;->x:Ljava/lang/String;

    move/from16 p1, p27

    iput-boolean p1, p0, Lvp/f4;->y:Z

    move-wide/from16 p1, p28

    iput-wide p1, p0, Lvp/f4;->z:J

    move/from16 p1, p30

    iput p1, p0, Lvp/f4;->A:I

    move-object/from16 p1, p31

    iput-object p1, p0, Lvp/f4;->B:Ljava/lang/String;

    move/from16 p1, p32

    iput p1, p0, Lvp/f4;->C:I

    move-wide/from16 p1, p33

    iput-wide p1, p0, Lvp/f4;->D:J

    move-object/from16 p1, p35

    iput-object p1, p0, Lvp/f4;->E:Ljava/lang/String;

    move-object/from16 p1, p36

    iput-object p1, p0, Lvp/f4;->F:Ljava/lang/String;

    move-wide/from16 p1, p37

    iput-wide p1, p0, Lvp/f4;->G:J

    move/from16 p1, p39

    iput p1, p0, Lvp/f4;->H:I

    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 5

    .line 1
    const/16 p2, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    const/4 v0, 0x2

    .line 8
    iget-object v1, p0, Lvp/f4;->d:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x3

    .line 14
    iget-object v1, p0, Lvp/f4;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lvp/f4;->f:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    invoke-static {p1, v0, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x5

    .line 26
    iget-object v2, p0, Lvp/f4;->g:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {p1, v2, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 29
    .line 30
    .line 31
    const/4 v0, 0x6

    .line 32
    const/16 v2, 0x8

    .line 33
    .line 34
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 35
    .line 36
    .line 37
    iget-wide v3, p0, Lvp/f4;->h:J

    .line 38
    .line 39
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 40
    .line 41
    .line 42
    const/4 v0, 0x7

    .line 43
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 44
    .line 45
    .line 46
    iget-wide v3, p0, Lvp/f4;->i:J

    .line 47
    .line 48
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 49
    .line 50
    .line 51
    iget-object v0, p0, Lvp/f4;->j:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p1, v0, v2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 54
    .line 55
    .line 56
    const/16 v0, 0x9

    .line 57
    .line 58
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 59
    .line 60
    .line 61
    iget-boolean v0, p0, Lvp/f4;->k:Z

    .line 62
    .line 63
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 64
    .line 65
    .line 66
    const/16 v0, 0xa

    .line 67
    .line 68
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 69
    .line 70
    .line 71
    iget-boolean v0, p0, Lvp/f4;->l:Z

    .line 72
    .line 73
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 74
    .line 75
    .line 76
    const/16 v0, 0xb

    .line 77
    .line 78
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 79
    .line 80
    .line 81
    iget-wide v3, p0, Lvp/f4;->m:J

    .line 82
    .line 83
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 84
    .line 85
    .line 86
    const/16 v0, 0xc

    .line 87
    .line 88
    iget-object v3, p0, Lvp/f4;->n:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 91
    .line 92
    .line 93
    const/16 v0, 0xe

    .line 94
    .line 95
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 96
    .line 97
    .line 98
    iget-wide v3, p0, Lvp/f4;->o:J

    .line 99
    .line 100
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 101
    .line 102
    .line 103
    const/16 v0, 0xf

    .line 104
    .line 105
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 106
    .line 107
    .line 108
    iget v0, p0, Lvp/f4;->p:I

    .line 109
    .line 110
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 111
    .line 112
    .line 113
    const/16 v0, 0x10

    .line 114
    .line 115
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 116
    .line 117
    .line 118
    iget-boolean v0, p0, Lvp/f4;->q:Z

    .line 119
    .line 120
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 121
    .line 122
    .line 123
    const/16 v0, 0x12

    .line 124
    .line 125
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 126
    .line 127
    .line 128
    iget-boolean v0, p0, Lvp/f4;->r:Z

    .line 129
    .line 130
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 131
    .line 132
    .line 133
    iget-object v0, p0, Lvp/f4;->s:Ljava/lang/Boolean;

    .line 134
    .line 135
    if-nez v0, :cond_0

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_0
    const/16 v3, 0x15

    .line 139
    .line 140
    invoke-static {p1, v3, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 148
    .line 149
    .line 150
    :goto_0
    const/16 v0, 0x16

    .line 151
    .line 152
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 153
    .line 154
    .line 155
    iget-wide v3, p0, Lvp/f4;->t:J

    .line 156
    .line 157
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 158
    .line 159
    .line 160
    const/16 v0, 0x17

    .line 161
    .line 162
    iget-object v3, p0, Lvp/f4;->u:Ljava/util/List;

    .line 163
    .line 164
    invoke-static {p1, v0, v3}, Ljp/dc;->p(Landroid/os/Parcel;ILjava/util/List;)V

    .line 165
    .line 166
    .line 167
    const/16 v0, 0x19

    .line 168
    .line 169
    iget-object v3, p0, Lvp/f4;->v:Ljava/lang/String;

    .line 170
    .line 171
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 172
    .line 173
    .line 174
    const/16 v0, 0x1a

    .line 175
    .line 176
    iget-object v3, p0, Lvp/f4;->w:Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 179
    .line 180
    .line 181
    const/16 v0, 0x1b

    .line 182
    .line 183
    iget-object v3, p0, Lvp/f4;->x:Ljava/lang/String;

    .line 184
    .line 185
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 186
    .line 187
    .line 188
    const/16 v0, 0x1c

    .line 189
    .line 190
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 191
    .line 192
    .line 193
    iget-boolean v0, p0, Lvp/f4;->y:Z

    .line 194
    .line 195
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 196
    .line 197
    .line 198
    const/16 v0, 0x1d

    .line 199
    .line 200
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 201
    .line 202
    .line 203
    iget-wide v3, p0, Lvp/f4;->z:J

    .line 204
    .line 205
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 206
    .line 207
    .line 208
    const/16 v0, 0x1e

    .line 209
    .line 210
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 211
    .line 212
    .line 213
    iget v0, p0, Lvp/f4;->A:I

    .line 214
    .line 215
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 216
    .line 217
    .line 218
    const/16 v0, 0x1f

    .line 219
    .line 220
    iget-object v3, p0, Lvp/f4;->B:Ljava/lang/String;

    .line 221
    .line 222
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 223
    .line 224
    .line 225
    const/16 v0, 0x20

    .line 226
    .line 227
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 228
    .line 229
    .line 230
    iget v0, p0, Lvp/f4;->C:I

    .line 231
    .line 232
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 233
    .line 234
    .line 235
    const/16 v0, 0x22

    .line 236
    .line 237
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 238
    .line 239
    .line 240
    iget-wide v3, p0, Lvp/f4;->D:J

    .line 241
    .line 242
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 243
    .line 244
    .line 245
    const/16 v0, 0x23

    .line 246
    .line 247
    iget-object v3, p0, Lvp/f4;->E:Ljava/lang/String;

    .line 248
    .line 249
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 250
    .line 251
    .line 252
    const/16 v0, 0x24

    .line 253
    .line 254
    iget-object v3, p0, Lvp/f4;->F:Ljava/lang/String;

    .line 255
    .line 256
    invoke-static {p1, v3, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 257
    .line 258
    .line 259
    const/16 v0, 0x25

    .line 260
    .line 261
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 262
    .line 263
    .line 264
    iget-wide v2, p0, Lvp/f4;->G:J

    .line 265
    .line 266
    invoke-virtual {p1, v2, v3}, Landroid/os/Parcel;->writeLong(J)V

    .line 267
    .line 268
    .line 269
    const/16 v0, 0x26

    .line 270
    .line 271
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 272
    .line 273
    .line 274
    iget p0, p0, Lvp/f4;->H:I

    .line 275
    .line 276
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 277
    .line 278
    .line 279
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 280
    .line 281
    .line 282
    return-void
.end method
