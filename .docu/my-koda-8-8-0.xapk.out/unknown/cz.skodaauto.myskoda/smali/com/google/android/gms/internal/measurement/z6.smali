.class public final enum Lcom/google/android/gms/internal/measurement/z6;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum f:Lcom/google/android/gms/internal/measurement/z6;

.field public static final enum g:Lcom/google/android/gms/internal/measurement/z6;

.field public static final synthetic h:[Lcom/google/android/gms/internal/measurement/z6;


# instance fields
.field public final d:Lcom/google/android/gms/internal/measurement/a7;

.field public final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 23

    .line 1
    new-instance v1, Lcom/google/android/gms/internal/measurement/z6;

    .line 2
    .line 3
    sget-object v0, Lcom/google/android/gms/internal/measurement/a7;->g:Lcom/google/android/gms/internal/measurement/a7;

    .line 4
    .line 5
    const-string v2, "DOUBLE"

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x1

    .line 9
    invoke-direct {v1, v2, v3, v0, v4}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lcom/google/android/gms/internal/measurement/z6;

    .line 13
    .line 14
    sget-object v0, Lcom/google/android/gms/internal/measurement/a7;->f:Lcom/google/android/gms/internal/measurement/a7;

    .line 15
    .line 16
    const-string v5, "FLOAT"

    .line 17
    .line 18
    const/4 v6, 0x5

    .line 19
    invoke-direct {v2, v5, v4, v0, v6}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lcom/google/android/gms/internal/measurement/z6;

    .line 23
    .line 24
    sget-object v5, Lcom/google/android/gms/internal/measurement/a7;->e:Lcom/google/android/gms/internal/measurement/a7;

    .line 25
    .line 26
    const-string v7, "INT64"

    .line 27
    .line 28
    const/4 v8, 0x2

    .line 29
    invoke-direct {v0, v7, v8, v5, v3}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 30
    .line 31
    .line 32
    new-instance v7, Lcom/google/android/gms/internal/measurement/z6;

    .line 33
    .line 34
    const-string v9, "UINT64"

    .line 35
    .line 36
    const/4 v10, 0x3

    .line 37
    invoke-direct {v7, v9, v10, v5, v3}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 38
    .line 39
    .line 40
    new-instance v9, Lcom/google/android/gms/internal/measurement/z6;

    .line 41
    .line 42
    sget-object v11, Lcom/google/android/gms/internal/measurement/a7;->d:Lcom/google/android/gms/internal/measurement/a7;

    .line 43
    .line 44
    const-string v12, "INT32"

    .line 45
    .line 46
    const/4 v13, 0x4

    .line 47
    invoke-direct {v9, v12, v13, v11, v3}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 48
    .line 49
    .line 50
    new-instance v12, Lcom/google/android/gms/internal/measurement/z6;

    .line 51
    .line 52
    const-string v13, "FIXED64"

    .line 53
    .line 54
    invoke-direct {v12, v13, v6, v5, v4}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 55
    .line 56
    .line 57
    move-object v13, v7

    .line 58
    new-instance v7, Lcom/google/android/gms/internal/measurement/z6;

    .line 59
    .line 60
    const-string v14, "FIXED32"

    .line 61
    .line 62
    const/4 v15, 0x6

    .line 63
    invoke-direct {v7, v14, v15, v11, v6}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 64
    .line 65
    .line 66
    new-instance v14, Lcom/google/android/gms/internal/measurement/z6;

    .line 67
    .line 68
    sget-object v15, Lcom/google/android/gms/internal/measurement/a7;->h:Lcom/google/android/gms/internal/measurement/a7;

    .line 69
    .line 70
    const-string v4, "BOOL"

    .line 71
    .line 72
    const/4 v6, 0x7

    .line 73
    invoke-direct {v14, v4, v6, v15, v3}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 74
    .line 75
    .line 76
    move-object v4, v9

    .line 77
    new-instance v9, Lcom/google/android/gms/internal/measurement/z6;

    .line 78
    .line 79
    const/16 v6, 0x8

    .line 80
    .line 81
    sget-object v15, Lcom/google/android/gms/internal/measurement/a7;->i:Lcom/google/android/gms/internal/measurement/a7;

    .line 82
    .line 83
    const-string v3, "STRING"

    .line 84
    .line 85
    invoke-direct {v9, v3, v6, v15, v8}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 86
    .line 87
    .line 88
    sput-object v9, Lcom/google/android/gms/internal/measurement/z6;->f:Lcom/google/android/gms/internal/measurement/z6;

    .line 89
    .line 90
    new-instance v3, Lcom/google/android/gms/internal/measurement/z6;

    .line 91
    .line 92
    sget-object v6, Lcom/google/android/gms/internal/measurement/a7;->l:Lcom/google/android/gms/internal/measurement/a7;

    .line 93
    .line 94
    const-string v15, "GROUP"

    .line 95
    .line 96
    const/16 v8, 0x9

    .line 97
    .line 98
    invoke-direct {v3, v15, v8, v6, v10}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 99
    .line 100
    .line 101
    sput-object v3, Lcom/google/android/gms/internal/measurement/z6;->g:Lcom/google/android/gms/internal/measurement/z6;

    .line 102
    .line 103
    new-instance v8, Lcom/google/android/gms/internal/measurement/z6;

    .line 104
    .line 105
    const-string v10, "MESSAGE"

    .line 106
    .line 107
    const/16 v15, 0xa

    .line 108
    .line 109
    move-object/from16 v20, v0

    .line 110
    .line 111
    const/4 v0, 0x2

    .line 112
    invoke-direct {v8, v10, v15, v6, v0}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 113
    .line 114
    .line 115
    move-object v6, v12

    .line 116
    new-instance v12, Lcom/google/android/gms/internal/measurement/z6;

    .line 117
    .line 118
    const/16 v10, 0xb

    .line 119
    .line 120
    sget-object v15, Lcom/google/android/gms/internal/measurement/a7;->j:Lcom/google/android/gms/internal/measurement/a7;

    .line 121
    .line 122
    move-object/from16 v19, v1

    .line 123
    .line 124
    const-string v1, "BYTES"

    .line 125
    .line 126
    invoke-direct {v12, v1, v10, v15, v0}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 127
    .line 128
    .line 129
    move-object v0, v4

    .line 130
    move-object v4, v13

    .line 131
    new-instance v13, Lcom/google/android/gms/internal/measurement/z6;

    .line 132
    .line 133
    const-string v1, "UINT32"

    .line 134
    .line 135
    const/16 v10, 0xc

    .line 136
    .line 137
    const/4 v15, 0x0

    .line 138
    invoke-direct {v13, v1, v10, v11, v15}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 139
    .line 140
    .line 141
    move-object v1, v8

    .line 142
    move-object v8, v14

    .line 143
    new-instance v14, Lcom/google/android/gms/internal/measurement/z6;

    .line 144
    .line 145
    sget-object v10, Lcom/google/android/gms/internal/measurement/a7;->k:Lcom/google/android/gms/internal/measurement/a7;

    .line 146
    .line 147
    move-object/from16 v21, v0

    .line 148
    .line 149
    const-string v0, "ENUM"

    .line 150
    .line 151
    move-object/from16 v22, v1

    .line 152
    .line 153
    const/16 v1, 0xd

    .line 154
    .line 155
    invoke-direct {v14, v0, v1, v10, v15}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 156
    .line 157
    .line 158
    new-instance v15, Lcom/google/android/gms/internal/measurement/z6;

    .line 159
    .line 160
    const-string v0, "SFIXED32"

    .line 161
    .line 162
    const/16 v1, 0xe

    .line 163
    .line 164
    const/4 v10, 0x5

    .line 165
    invoke-direct {v15, v0, v1, v11, v10}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 166
    .line 167
    .line 168
    new-instance v0, Lcom/google/android/gms/internal/measurement/z6;

    .line 169
    .line 170
    const-string v1, "SFIXED64"

    .line 171
    .line 172
    const/16 v10, 0xf

    .line 173
    .line 174
    move-object/from16 v17, v2

    .line 175
    .line 176
    const/4 v2, 0x1

    .line 177
    invoke-direct {v0, v1, v10, v5, v2}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 178
    .line 179
    .line 180
    new-instance v1, Lcom/google/android/gms/internal/measurement/z6;

    .line 181
    .line 182
    const-string v2, "SINT32"

    .line 183
    .line 184
    const/16 v10, 0x10

    .line 185
    .line 186
    move-object/from16 v16, v0

    .line 187
    .line 188
    const/4 v0, 0x0

    .line 189
    invoke-direct {v1, v2, v10, v11, v0}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 190
    .line 191
    .line 192
    new-instance v2, Lcom/google/android/gms/internal/measurement/z6;

    .line 193
    .line 194
    const-string v10, "SINT64"

    .line 195
    .line 196
    const/16 v11, 0x11

    .line 197
    .line 198
    invoke-direct {v2, v10, v11, v5, v0}, Lcom/google/android/gms/internal/measurement/z6;-><init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V

    .line 199
    .line 200
    .line 201
    move-object/from16 v18, v2

    .line 202
    .line 203
    move-object v10, v3

    .line 204
    move-object/from16 v2, v17

    .line 205
    .line 206
    move-object/from16 v3, v20

    .line 207
    .line 208
    move-object/from16 v5, v21

    .line 209
    .line 210
    move-object/from16 v11, v22

    .line 211
    .line 212
    move-object/from16 v17, v1

    .line 213
    .line 214
    move-object/from16 v1, v19

    .line 215
    .line 216
    filled-new-array/range {v1 .. v18}, [Lcom/google/android/gms/internal/measurement/z6;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    sput-object v0, Lcom/google/android/gms/internal/measurement/z6;->h:[Lcom/google/android/gms/internal/measurement/z6;

    .line 221
    .line 222
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILcom/google/android/gms/internal/measurement/a7;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/z6;->d:Lcom/google/android/gms/internal/measurement/a7;

    .line 5
    .line 6
    iput p4, p0, Lcom/google/android/gms/internal/measurement/z6;->e:I

    .line 7
    .line 8
    return-void
.end method

.method public static values()[Lcom/google/android/gms/internal/measurement/z6;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/z6;->h:[Lcom/google/android/gms/internal/measurement/z6;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/gms/internal/measurement/z6;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/gms/internal/measurement/z6;

    .line 8
    .line 9
    return-object v0
.end method
