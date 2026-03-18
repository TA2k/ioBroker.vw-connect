.class public abstract Li31/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/List;

.field public static final b:Ljava/util/List;

.field public static final c:Li31/d;

.field public static final d:Li31/d;

.field public static final e:Li31/d;

.field public static final f:Li31/d;

.field public static final g:Ljava/util/List;

.field public static final h:Li31/e0;

.field public static final i:Ljava/util/List;

.field public static final j:Li31/h;

.field public static final k:Li31/d0;


# direct methods
.method static constructor <clinit>()V
    .locals 35

    .line 1
    sget-object v0, Li31/w;->f:Li31/w;

    .line 2
    .line 3
    sget-object v1, Li31/w;->h:Li31/w;

    .line 4
    .line 5
    const-string v2, "Other Warning 1"

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    const-string v4, "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAABBVBMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQECAgIDAwMGBgYHBwcJCQkLCwsQEBASEhIWFhYZGRkdHR0gICAkJCQoKCgrKysxMTE1NTU7Ozs/Pz9LS0tMTExZWVlaWlpmZmZnZ2d0dHR1dXWBgYGCgoKIiIiOjo6Pj4+cnJydnZ2pqamqqqq2tra7u7vCwsLGxsbMzMzPz8/Z2dnc3Nzg4ODj4+Pq6urt7e3w8PDy8vL19fX29vb6+vr7+/v9/f3+/v7///+vAVyLAAAAHHRSTlMACRIbICMqR05ga4qXpq++xdfZ3ebr8PP5/P3+GdPduwAAAAFiS0dEVgoN6YkAAAFeSURBVEjH3ZPFUgNREEUHCxI0WOQAwSG4u7tbuP//KSyIjPRkZqpYcdf3VL/uesdx/igDg8n6LdCaCChAIUk/DZBOAABA/H7mF8gkGbC5ATTF7GeheP8wCdl4/XZgX9oDOuKedO5VepuPedoe4EySToHeeBuvlCWpvBrrtEMwdi1J0s0YDEf1m4FtVbIFNEcAOZh6rAJP05Br3O8EDlXLAdAVtfHCex34WIzYuw+4kCvnQH/jAWvfbkDrDUeMwPitJAlAknQ3AaNh/TZgV15AO0Aq/BPNPPuBl9nQL5UGTuQHdAx0h2289BkEvpZD9s4AlwoCugIGQ7yUBci2NQvFexswba14aQKmrRUvbcCwtealCRi21ry0gYCtLi/t+Gz1eGnHa6vHS+tJPlt9XpqAx1aflzbgsjXgpQm4bA16aadqa93LiFRsTQGlo1gpASknT6LkHRLGySXr55x/kB/U5/3e0TryPgAAAABJRU5ErkJggg=="

    .line 9
    .line 10
    invoke-static {v2, v3, v4, v1, v3}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v2, "Yellow Warning 2"

    .line 15
    .line 16
    const/4 v13, 0x2

    .line 17
    const-string v6, "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAABDlBMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQACAgADAgAGBQAHBQAJBwALCAAQDAASDgAWEQEZEwEdFgEgGAEkGwEoHgErIQExJQE1KAE7LQI/MAJLOQJMOgJZQwJaRAJmTQNnTgN0WAN1WQOBYgSCYgSIZwSOawSPbAScdgSddwSpgAWqgQW2igW7jgXCkwXGlgXMmgbPnQbZpAbcpwbgqgbjrAbqsQbtswfwtgfytwf1uQf2ugf6vQf7vgf9vwf+wAf/wQf///8ZZOevAAAAHnRSTlMACBAXHCAmQEdXYn+Mm6Szu8nQ1d/k6u72+fr8/f4KRLSqAAAAAWJLR0RZmrL0GAAAAWFJREFUSMfdk1VTw2AURIMVKRqsSE+huLu7Q3Hf//9LeKCUyE2TzPDEPu+Zm/0mx3H+KF1uun4d1KcChmE4TT8LkE0BAEDyvvsNuGkOrK8BNQn7OSiWbscgl6zfCOxKO0BTIiAP00/S80zCp20DTiTpGGhPtnjpQ5I+lhM9bQ8ULiVJuipAb1y/FthUORtAbQwwCON3P8D9BAxW7zcD+6pkD2iJWzz78gu8zsXs7gDO5Mkp0Fn9wMqnF9Bq1RN9MHItSQKQJN2MQn9UvwHYlh/QFpCJ9nLyIQg8TkX+UlngSEFAh0Br1OKFtzDwvhix2wXOFQZ0AXRHeCkLkG1rDoolGzBtLXtpAqatZS9twLC14qUJGLZWvLSBkK0eL+0EbPV5acdvq89L65MCtga8NAGfrQEvbcBja8hLE/DYGvbSzo+tv17GpGxrBpg/SJR5IOMMkSpDDinjDOTT1PMDzj/IF0xxBkrA8g6LAAAAAElFTkSuQmCC"

    .line 18
    .line 19
    invoke-static {v2, v13, v6, v0, v13}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    sget-object v7, Li31/w;->g:Li31/w;

    .line 24
    .line 25
    const-string v8, "Green Warning 3"

    .line 26
    .line 27
    const/4 v9, 0x3

    .line 28
    const-string v10, "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAABFFBMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQABAgEBAwECBAICBQICBgMECQQECgQFDAUFDgYGEAcHEggIFAgJFgkJGAoLGwwMHgwNIQ4OIw8QKhIRKhIUMhUWORgXORgZQRsaQRwcSB4dSB8eTCAfTyEfUCIiVyUlXiglXygoZSspaCwrbC4rbi8tcjAtczEweTMwezQxfTUyfjUzgjc0hDg1hjg1hzk2iDo2iTo3izs3jDs4jTw4jjz///8fYEamAAAAJHRSTlMABgwPEhgeMjdFTmdzgYmZm6Git73Jz9fd5ery9Pf4+vv8/f6o1/rCAAAAAWJLR0RbdLyVNAAAAWdJREFUSMfd09VSw2AUReFgRYoXLVBsleLu7u7e/f4Pwk1bIidpMsMV+/qsmeSf+Rznj9bZney+DuoTBSMwkuQ+DZBOEEwCTMa/zwBAJnYA7GwDNTHvs1B4eJyGbLz7RuBQOgCaYgVjsPAmvS/CaJz7NuBcks6B9nh/vF6UpOIGUP2+F/I3kiTd5qGv2n0tsKvSdoHaKsEQzDyVg+dZGIq+bwaOVdkR0BIZTMDSx2/wuQwTUfcdwKVcuwC6op90s+gOtBX5tP2Qv5MkAUiS7qdgIOy+AdiXN9AekAoJcjD34g9e50O1poEz+QOdAq1hLle/gsH3WojWDHClYKBroCfEpaxAttYsFB7swNRacmkGptaSSzswtFZcmoGhteLSDgJaXS7t+bR6XNrzavW4tD7Jp9Xn0gw8Wn0u7cClNeDSDFxagy7tlbX+uqyyktYUsHISaytAyhkm0YYdEs4ZzI0nWG7Q+Qf7AW9BFaCO9clCAAAAAElFTkSuQmCC"

    .line 29
    .line 30
    invoke-static {v8, v9, v10, v7, v9}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    const-string v9, "Other Warning 4"

    .line 35
    .line 36
    const/4 v14, 0x4

    .line 37
    invoke-static {v9, v14, v4, v1, v14}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    const-string v4, "Yellow Warning 5"

    .line 42
    .line 43
    const/4 v15, 0x5

    .line 44
    invoke-static {v4, v15, v6, v0, v15}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 45
    .line 46
    .line 47
    move-result-object v9

    .line 48
    sget-object v0, Li31/w;->e:Li31/w;

    .line 49
    .line 50
    const-string v4, "Red Warning 6"

    .line 51
    .line 52
    const/4 v6, 0x6

    .line 53
    const-string v11, "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAABF1BMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAACAAACAQEFAQEGAQEHAgIJAgINAwMPAwMSBAQVBQUYBQUaBgYeBwchBwckCAgpCQksCgoxCws0DAw+Dg4/Dg5KEBBKERFUExNVExNgFRVhFhZrGBhsGBhxGRl1Ghp2GhqBHR2CHR2MHx+NHx+XIiKbIiKhJCSkJCSpJiarJia0KCi2KSm5KSm8KirCKyvELCzHLCzILS3LLS3MLS3PLi7QLi7RLy/SLy/TLy/////g3/tOAAAAIXRSTlMABw4TFxwiOT9OWHSAj5enr7a9xcrV2+Ln8fP3+fv8/f7tGJVhAAAAAWJLR0Rc6tgAlwAAAWRJREFUSMfdk9VSw2AUBoMVKV6sSOkWd3d3d+d7//fgglIiJ2kywxV7/e0k559Zx/kj2tqT7augOpEwAANJ9mmAdAIBAOLvM99CJskH1laBipj7LIzc3I5CNt6+FtiRtoG6WMIgTD1Jz9OQi7NvAo4l6Qhojnfx4ockfSzFetpOKFxIknRZgK5y+0pgQ0XWgcoyQh+M3f0I9+PQF72vB/ZUYhdoiBTyMPPyK7zOQj5q3wKcysUJ0Br9pMufbkErkU/bDUNXkiQASdL1MPSE7WuALXkFbQKp8C4nHvzC42RorWngUH5BB0Bj2MXzb0HhfSHk7gxwpqCgc6AjpEtZguxaszByYwtmrcUuTcGstdilLRi1lro0BaPWUpe2EKjV1aWNr1ZPlzbeWj1dWr/kq9XXpSl4avV1aQuuWgNdmoKr1mCXNj+1/nZZhmKtKWBuPxZzQMrpJxH9DglxenP5BOR6nX/AF4thErJ8m6e6AAAAAElFTkSuQmCC"

    .line 54
    .line 55
    invoke-static {v4, v6, v11, v0, v6}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    const-string v6, "Green Warning 7"

    .line 60
    .line 61
    const/4 v12, 0x7

    .line 62
    invoke-static {v6, v12, v10, v7, v12}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 63
    .line 64
    .line 65
    move-result-object v6

    .line 66
    const-string v7, "Red Warning 8"

    .line 67
    .line 68
    const/16 v10, 0x8

    .line 69
    .line 70
    invoke-static {v7, v10, v11, v0, v10}, Li31/h0;->a(Ljava/lang/String;ILjava/lang/String;Li31/w;I)Li31/h0;

    .line 71
    .line 72
    .line 73
    move-result-object v12

    .line 74
    move-object v10, v4

    .line 75
    move-object v11, v6

    .line 76
    move-object v7, v8

    .line 77
    move-object v8, v1

    .line 78
    move-object v6, v2

    .line 79
    filled-new-array/range {v5 .. v12}, [Li31/h0;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    sput-object v0, Li31/x;->a:Ljava/util/List;

    .line 88
    .line 89
    new-instance v0, Li31/y;

    .line 90
    .line 91
    const-string v1, "Brake pads"

    .line 92
    .line 93
    const/4 v2, 0x0

    .line 94
    invoke-direct {v0, v1, v15, v2, v3}, Li31/y;-><init>(Ljava/lang/String;IIZ)V

    .line 95
    .line 96
    .line 97
    new-instance v1, Li31/y;

    .line 98
    .line 99
    const-string v4, "Cell degradation"

    .line 100
    .line 101
    const/16 v5, 0x3c

    .line 102
    .line 103
    invoke-direct {v1, v4, v5, v2, v3}, Li31/y;-><init>(Ljava/lang/String;IIZ)V

    .line 104
    .line 105
    .line 106
    filled-new-array {v0, v1}, [Li31/y;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    sput-object v0, Li31/x;->b:Ljava/util/List;

    .line 115
    .line 116
    new-instance v0, Li31/f;

    .line 117
    .line 118
    const-string v1, "\u20ac"

    .line 119
    .line 120
    const-wide v4, 0x4056800000000000L    # 90.0

    .line 121
    .line 122
    .line 123
    .line 124
    .line 125
    invoke-direct {v0, v4, v5, v1}, Li31/f;-><init>(DLjava/lang/String;)V

    .line 126
    .line 127
    .line 128
    const-wide v4, 0x4086f80000000000L    # 735.0

    .line 129
    .line 130
    .line 131
    .line 132
    .line 133
    invoke-static {v0, v4, v5}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 134
    .line 135
    .line 136
    const-string v1, "SVCIT05"

    .line 137
    .line 138
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 139
    .line 140
    .line 141
    new-instance v15, Li31/e;

    .line 142
    .line 143
    const-wide v4, 0x408ab80000000000L    # 855.0

    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    invoke-static {v0, v4, v5}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 149
    .line 150
    .line 151
    move-result-object v20

    .line 152
    const-string v23, "Category 0 Service 0"

    .line 153
    .line 154
    const/16 v24, 0x0

    .line 155
    .line 156
    const-string v16, "oilServices"

    .line 157
    .line 158
    const-string v17, "Category 0"

    .line 159
    .line 160
    const-string v18, "Category 0 Service 0"

    .line 161
    .line 162
    sget-object v29, Lmx0/s;->d:Lmx0/s;

    .line 163
    .line 164
    const/16 v21, 0x1

    .line 165
    .line 166
    const-string v22, "SVC00"

    .line 167
    .line 168
    move-object/from16 v19, v29

    .line 169
    .line 170
    invoke-direct/range {v15 .. v24}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 171
    .line 172
    .line 173
    new-instance v25, Li31/e;

    .line 174
    .line 175
    const-string v33, "Category 1 Service 0"

    .line 176
    .line 177
    const/16 v34, 0x0

    .line 178
    .line 179
    const-string v26, "oilServices"

    .line 180
    .line 181
    const-string v27, "Category 1"

    .line 182
    .line 183
    const-string v28, "Category 1 Service 0"

    .line 184
    .line 185
    const/16 v30, 0x0

    .line 186
    .line 187
    const/16 v31, 0x1

    .line 188
    .line 189
    const-string v32, "SVC10"

    .line 190
    .line 191
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 192
    .line 193
    .line 194
    move-object/from16 v1, v25

    .line 195
    .line 196
    new-instance v25, Li31/e;

    .line 197
    .line 198
    const-wide v4, 0x40934c0000000000L    # 1235.0

    .line 199
    .line 200
    .line 201
    .line 202
    .line 203
    invoke-static {v0, v4, v5}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 204
    .line 205
    .line 206
    move-result-object v30

    .line 207
    const-string v33, "Category 1 Service 1"

    .line 208
    .line 209
    const/16 v34, 0x1

    .line 210
    .line 211
    const-string v26, "oilServices"

    .line 212
    .line 213
    const-string v27, "Category 1"

    .line 214
    .line 215
    const-string v28, "Category 1 Service 1"

    .line 216
    .line 217
    const-string v32, "SVC11"

    .line 218
    .line 219
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 220
    .line 221
    .line 222
    move-object/from16 v4, v25

    .line 223
    .line 224
    new-instance v25, Li31/e;

    .line 225
    .line 226
    const-string v33, "Category 1 Service 2"

    .line 227
    .line 228
    const/16 v34, 0x2

    .line 229
    .line 230
    const-string v26, "oilServices"

    .line 231
    .line 232
    const-string v27, "Category 1"

    .line 233
    .line 234
    const-string v28, "Category 1 Service 2"

    .line 235
    .line 236
    const/16 v30, 0x0

    .line 237
    .line 238
    const-string v32, "SVC12"

    .line 239
    .line 240
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 241
    .line 242
    .line 243
    move-object/from16 v5, v25

    .line 244
    .line 245
    new-instance v25, Li31/e;

    .line 246
    .line 247
    const-wide v6, 0x406d400000000000L    # 234.0

    .line 248
    .line 249
    .line 250
    .line 251
    .line 252
    invoke-static {v0, v6, v7}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 253
    .line 254
    .line 255
    move-result-object v30

    .line 256
    const-string v33, "Category 1 Service 3"

    .line 257
    .line 258
    const/16 v34, 0x3

    .line 259
    .line 260
    const-string v26, "oilServices"

    .line 261
    .line 262
    const-string v27, "Category 1"

    .line 263
    .line 264
    const-string v28, "Category 1 Service 3"

    .line 265
    .line 266
    const-string v32, "SVC13"

    .line 267
    .line 268
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 269
    .line 270
    .line 271
    move-object/from16 v6, v25

    .line 272
    .line 273
    new-instance v25, Li31/e;

    .line 274
    .line 275
    const-wide v7, 0x406d200000000000L    # 233.0

    .line 276
    .line 277
    .line 278
    .line 279
    .line 280
    invoke-static {v0, v7, v8}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 281
    .line 282
    .line 283
    move-result-object v30

    .line 284
    const-string v33, "Category 2 Service 0"

    .line 285
    .line 286
    const/16 v34, 0x0

    .line 287
    .line 288
    const-string v26, "oilServices"

    .line 289
    .line 290
    const-string v27, "Category 2"

    .line 291
    .line 292
    const-string v28, "Category 2 Service 0"

    .line 293
    .line 294
    const-string v32, "SVC20"

    .line 295
    .line 296
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 297
    .line 298
    .line 299
    move-object/from16 v7, v25

    .line 300
    .line 301
    new-instance v25, Li31/e;

    .line 302
    .line 303
    const-wide v8, 0x4083780000000000L    # 623.0

    .line 304
    .line 305
    .line 306
    .line 307
    .line 308
    invoke-static {v0, v8, v9}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 309
    .line 310
    .line 311
    move-result-object v30

    .line 312
    const-string v33, "Category 2 Service 1"

    .line 313
    .line 314
    const/16 v34, 0x1

    .line 315
    .line 316
    const-string v26, "oilServices"

    .line 317
    .line 318
    const-string v27, "Category 2"

    .line 319
    .line 320
    const-string v28, "Category 2 Service 1"

    .line 321
    .line 322
    const-string v32, "SVC21"

    .line 323
    .line 324
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 325
    .line 326
    .line 327
    move-object/from16 v8, v25

    .line 328
    .line 329
    new-instance v25, Li31/e;

    .line 330
    .line 331
    const-wide v9, 0x405b400000000000L    # 109.0

    .line 332
    .line 333
    .line 334
    .line 335
    .line 336
    invoke-static {v0, v9, v10}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 337
    .line 338
    .line 339
    move-result-object v30

    .line 340
    const-string v33, "Category 4 Service 0"

    .line 341
    .line 342
    const/16 v34, 0x0

    .line 343
    .line 344
    const-string v26, "oilServices"

    .line 345
    .line 346
    const-string v27, "Category 4"

    .line 347
    .line 348
    const-string v28, "Category 4 Service 0"

    .line 349
    .line 350
    const-string v32, "SVC40"

    .line 351
    .line 352
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 353
    .line 354
    .line 355
    move-object/from16 v9, v25

    .line 356
    .line 357
    new-instance v25, Li31/e;

    .line 358
    .line 359
    const-wide v10, 0x4080580000000000L    # 523.0

    .line 360
    .line 361
    .line 362
    .line 363
    .line 364
    invoke-static {v0, v10, v11}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 365
    .line 366
    .line 367
    move-result-object v30

    .line 368
    const-string v33, "Category 4 Service 1"

    .line 369
    .line 370
    const/16 v34, 0x1

    .line 371
    .line 372
    const-string v26, "oilServices"

    .line 373
    .line 374
    const-string v27, "Category 4"

    .line 375
    .line 376
    const-string v28, "Category 4 Service XX"

    .line 377
    .line 378
    const-string v32, "SVC41"

    .line 379
    .line 380
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 381
    .line 382
    .line 383
    move-object/from16 v10, v25

    .line 384
    .line 385
    new-instance v25, Li31/e;

    .line 386
    .line 387
    const-wide v11, 0x4085480000000000L    # 681.0

    .line 388
    .line 389
    .line 390
    .line 391
    .line 392
    invoke-static {v0, v11, v12}, Li31/f;->a(Li31/f;D)Li31/f;

    .line 393
    .line 394
    .line 395
    move-result-object v30

    .line 396
    const-string v33, "Category 4 Service 2"

    .line 397
    .line 398
    const/16 v34, 0x2

    .line 399
    .line 400
    const-string v26, "oilServices"

    .line 401
    .line 402
    const-string v27, "Category 4"

    .line 403
    .line 404
    const-string v28, "Category 4 Service 2"

    .line 405
    .line 406
    const-string v32, "SVC42"

    .line 407
    .line 408
    invoke-direct/range {v25 .. v34}, Li31/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Li31/f;ZLjava/lang/String;Ljava/lang/String;I)V

    .line 409
    .line 410
    .line 411
    move-object/from16 v0, v25

    .line 412
    .line 413
    new-instance v11, Li31/d;

    .line 414
    .line 415
    const-string v12, "Category Header 0"

    .line 416
    .line 417
    invoke-static {v15}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 418
    .line 419
    .line 420
    move-result-object v15

    .line 421
    const-string v14, "oilServices"

    .line 422
    .line 423
    invoke-direct {v11, v2, v14, v12, v15}, Li31/d;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 424
    .line 425
    .line 426
    sput-object v11, Li31/x;->c:Li31/d;

    .line 427
    .line 428
    new-instance v2, Li31/d;

    .line 429
    .line 430
    filled-new-array {v1, v4, v5, v6}, [Li31/e;

    .line 431
    .line 432
    .line 433
    move-result-object v1

    .line 434
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 435
    .line 436
    .line 437
    move-result-object v1

    .line 438
    const-string v4, "Category Header 1"

    .line 439
    .line 440
    invoke-direct {v2, v3, v14, v4, v1}, Li31/d;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 441
    .line 442
    .line 443
    sput-object v2, Li31/x;->d:Li31/d;

    .line 444
    .line 445
    new-instance v1, Li31/d;

    .line 446
    .line 447
    filled-new-array {v7, v8}, [Li31/e;

    .line 448
    .line 449
    .line 450
    move-result-object v2

    .line 451
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 452
    .line 453
    .line 454
    move-result-object v2

    .line 455
    const-string v4, "Category Header 2"

    .line 456
    .line 457
    invoke-direct {v1, v13, v14, v4, v2}, Li31/d;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 458
    .line 459
    .line 460
    sput-object v1, Li31/x;->e:Li31/d;

    .line 461
    .line 462
    new-instance v1, Li31/d;

    .line 463
    .line 464
    filled-new-array {v9, v10, v0}, [Li31/e;

    .line 465
    .line 466
    .line 467
    move-result-object v0

    .line 468
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 469
    .line 470
    .line 471
    move-result-object v0

    .line 472
    const-string v2, "Category Header 4"

    .line 473
    .line 474
    const/4 v4, 0x4

    .line 475
    invoke-direct {v1, v4, v14, v2, v0}, Li31/d;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 476
    .line 477
    .line 478
    sput-object v1, Li31/x;->f:Li31/d;

    .line 479
    .line 480
    new-instance v0, Li31/a;

    .line 481
    .line 482
    const-string v1, "Azaan"

    .line 483
    .line 484
    const-string v2, "Odling"

    .line 485
    .line 486
    const-string v4, "saId01"

    .line 487
    .line 488
    invoke-direct {v0, v4, v1, v2}, Li31/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    new-instance v1, Li31/a;

    .line 492
    .line 493
    const-string v2, "Levi"

    .line 494
    .line 495
    const-string v5, "Gibbs"

    .line 496
    .line 497
    const-string v6, "saId02"

    .line 498
    .line 499
    invoke-direct {v1, v6, v2, v5}, Li31/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    new-instance v2, Li31/a;

    .line 503
    .line 504
    const-string v5, "Ewan"

    .line 505
    .line 506
    const-string v7, "Conner"

    .line 507
    .line 508
    const-string v8, "saId03"

    .line 509
    .line 510
    invoke-direct {v2, v8, v5, v7}, Li31/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 511
    .line 512
    .line 513
    new-instance v5, Li31/a;

    .line 514
    .line 515
    const-string v7, "Haider"

    .line 516
    .line 517
    const-string v9, "Rollins"

    .line 518
    .line 519
    const-string v10, "saId04"

    .line 520
    .line 521
    invoke-direct {v5, v10, v7, v9}, Li31/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 522
    .line 523
    .line 524
    filled-new-array {v0, v1, v2, v5}, [Li31/a;

    .line 525
    .line 526
    .line 527
    move-result-object v0

    .line 528
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    sput-object v0, Li31/x;->g:Ljava/util/List;

    .line 533
    .line 534
    new-instance v11, Li31/e0;

    .line 535
    .line 536
    filled-new-array {v4, v6, v8, v10}, [Ljava/lang/String;

    .line 537
    .line 538
    .line 539
    move-result-object v1

    .line 540
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 541
    .line 542
    .line 543
    move-result-object v16

    .line 544
    const-string v12, "2025-04-18T09:00:00.000Z"

    .line 545
    .line 546
    const-string v13, "2025-04-18T10:00:00.000Z"

    .line 547
    .line 548
    const-string v14, ""

    .line 549
    .line 550
    const-string v15, ""

    .line 551
    .line 552
    invoke-direct/range {v11 .. v16}, Li31/e0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 553
    .line 554
    .line 555
    sput-object v11, Li31/x;->h:Li31/e0;

    .line 556
    .line 557
    const-string v18, "16:00"

    .line 558
    .line 559
    const-string v19, "17:00"

    .line 560
    .line 561
    const-string v12, "09:00"

    .line 562
    .line 563
    const-string v13, "10:00"

    .line 564
    .line 565
    const-string v14, "11:00"

    .line 566
    .line 567
    const-string v15, "13:00"

    .line 568
    .line 569
    const-string v16, "14:00"

    .line 570
    .line 571
    const-string v17, "15:00"

    .line 572
    .line 573
    filled-new-array/range {v12 .. v19}, [Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v1

    .line 577
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 578
    .line 579
    .line 580
    move-result-object v1

    .line 581
    sput-object v1, Li31/x;->i:Ljava/util/List;

    .line 582
    .line 583
    new-instance v1, Li31/h;

    .line 584
    .line 585
    const-string v2, "2025-04-18"

    .line 586
    .line 587
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 588
    .line 589
    .line 590
    move-result-object v4

    .line 591
    const-string v2, "2025-04-19"

    .line 592
    .line 593
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 594
    .line 595
    .line 596
    move-result-object v5

    .line 597
    const-string v2, "2025-04-20"

    .line 598
    .line 599
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 600
    .line 601
    .line 602
    move-result-object v6

    .line 603
    const-string v2, "2025-04-21"

    .line 604
    .line 605
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 606
    .line 607
    .line 608
    move-result-object v7

    .line 609
    const-string v2, "2025-04-22"

    .line 610
    .line 611
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 612
    .line 613
    .line 614
    move-result-object v8

    .line 615
    const-string v2, "2025-04-23"

    .line 616
    .line 617
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 618
    .line 619
    .line 620
    move-result-object v9

    .line 621
    const-string v2, "2025-04-24"

    .line 622
    .line 623
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 624
    .line 625
    .line 626
    move-result-object v10

    .line 627
    const-string v2, "2025-04-25"

    .line 628
    .line 629
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 630
    .line 631
    .line 632
    move-result-object v11

    .line 633
    const-string v2, "2025-04-26"

    .line 634
    .line 635
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 636
    .line 637
    .line 638
    move-result-object v12

    .line 639
    const-string v2, "2025-04-27"

    .line 640
    .line 641
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 642
    .line 643
    .line 644
    move-result-object v13

    .line 645
    const-string v2, "2025-04-28"

    .line 646
    .line 647
    invoke-static {v2}, Li31/x;->a(Ljava/lang/String;)Li31/i;

    .line 648
    .line 649
    .line 650
    move-result-object v14

    .line 651
    filled-new-array/range {v4 .. v14}, [Li31/i;

    .line 652
    .line 653
    .line 654
    move-result-object v2

    .line 655
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 656
    .line 657
    .line 658
    move-result-object v2

    .line 659
    const/16 v4, 0x96

    .line 660
    .line 661
    invoke-direct {v1, v0, v2, v4}, Li31/h;-><init>(Ljava/util/List;Ljava/util/List;I)V

    .line 662
    .line 663
    .line 664
    sput-object v1, Li31/x;->j:Li31/h;

    .line 665
    .line 666
    new-instance v0, Li31/d0;

    .line 667
    .line 668
    const-string v1, "00217"

    .line 669
    .line 670
    const-string v2, "Spreng Gesellschaft m.b.H."

    .line 671
    .line 672
    invoke-direct {v0, v1, v2, v3}, Li31/d0;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 673
    .line 674
    .line 675
    sput-object v0, Li31/x;->k:Li31/d0;

    .line 676
    .line 677
    return-void
.end method

.method public static final a(Ljava/lang/String;)Li31/i;
    .locals 9

    .line 1
    sget-object v0, Li31/x;->i:Ljava/util/List;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Iterable;

    .line 4
    .line 5
    new-instance v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    const/16 v2, 0xa

    .line 8
    .line 9
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    move-object v7, v2

    .line 31
    check-cast v7, Ljava/lang/String;

    .line 32
    .line 33
    const-string v2, "T"

    .line 34
    .line 35
    const-string v3, ":00.000Z"

    .line 36
    .line 37
    invoke-static {p0, v2, v7, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    sget-object v2, Li31/x;->h:Li31/e0;

    .line 42
    .line 43
    iget-object v5, v2, Li31/e0;->b:Ljava/lang/String;

    .line 44
    .line 45
    iget-object v6, v2, Li31/e0;->c:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v8, v2, Li31/e0;->e:Ljava/util/List;

    .line 48
    .line 49
    const-string v2, "start"

    .line 50
    .line 51
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string v2, "end"

    .line 55
    .line 56
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v2, "expectedReturnTime"

    .line 60
    .line 61
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string v2, "startLocalTime"

    .line 65
    .line 66
    invoke-static {v7, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    new-instance v3, Li31/e0;

    .line 70
    .line 71
    invoke-direct/range {v3 .. v8}, Li31/e0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_0
    new-instance v0, Li31/i;

    .line 79
    .line 80
    const/4 v2, 0x1

    .line 81
    invoke-direct {v0, p0, v1, v2}, Li31/i;-><init>(Ljava/lang/String;Ljava/util/List;Z)V

    .line 82
    .line 83
    .line 84
    return-object v0
.end method
