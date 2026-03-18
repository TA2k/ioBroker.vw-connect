.class public abstract Lt61/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ltechnology/cariad/cat/genx/protocol/Address$Companion;)Ljava/util/Set;
    .locals 24

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/genx/protocol/Address$Companion;->getVehicleDataRequest()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/genx/protocol/Address$Companion;->getVehicleDataResponse()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    new-instance v3, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 17
    .line 18
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;->Companion:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;

    .line 19
    .line 20
    invoke-static {v0}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    sget-object v5, Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    const/4 v7, 0x0

    .line 28
    invoke-direct {v3, v4, v6, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 29
    .line 30
    .line 31
    new-instance v4, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 32
    .line 33
    invoke-static {v0}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 34
    .line 35
    .line 36
    move-result-object v8

    .line 37
    invoke-direct {v4, v8, v6, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 38
    .line 39
    .line 40
    new-instance v8, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 41
    .line 42
    invoke-static {v0}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 43
    .line 44
    .line 45
    move-result-object v9

    .line 46
    const/4 v10, 0x1

    .line 47
    invoke-direct {v8, v9, v10, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 48
    .line 49
    .line 50
    new-instance v9, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 51
    .line 52
    invoke-static {v0}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 53
    .line 54
    .line 55
    move-result-object v11

    .line 56
    invoke-direct {v9, v11, v10, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 57
    .line 58
    .line 59
    new-instance v11, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 60
    .line 61
    invoke-static {v0}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 62
    .line 63
    .line 64
    move-result-object v12

    .line 65
    const/4 v13, 0x2

    .line 66
    invoke-direct {v11, v12, v13, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 67
    .line 68
    .line 69
    move-object v12, v8

    .line 70
    new-instance v8, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 71
    .line 72
    invoke-static {v0}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 73
    .line 74
    .line 75
    move-result-object v14

    .line 76
    invoke-direct {v8, v14, v13, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 77
    .line 78
    .line 79
    move-object v14, v9

    .line 80
    new-instance v9, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 81
    .line 82
    invoke-static {v0}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 83
    .line 84
    .line 85
    move-result-object v15

    .line 86
    const/4 v13, 0x3

    .line 87
    invoke-direct {v9, v15, v13, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 88
    .line 89
    .line 90
    new-instance v15, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 91
    .line 92
    invoke-static {v0}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 93
    .line 94
    .line 95
    move-result-object v10

    .line 96
    invoke-direct {v15, v10, v13, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 97
    .line 98
    .line 99
    move-object v10, v11

    .line 100
    new-instance v11, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 101
    .line 102
    invoke-static {v0}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 103
    .line 104
    .line 105
    move-result-object v13

    .line 106
    const/4 v6, 0x5

    .line 107
    invoke-direct {v11, v13, v6, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 108
    .line 109
    .line 110
    move-object v13, v12

    .line 111
    new-instance v12, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 112
    .line 113
    move-object/from16 v19, v0

    .line 114
    .line 115
    invoke-static/range {v19 .. v19}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    invoke-direct {v12, v0, v6, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 120
    .line 121
    .line 122
    move-object v0, v13

    .line 123
    new-instance v13, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 124
    .line 125
    invoke-static/range {v19 .. v19}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    move-object/from16 v20, v0

    .line 130
    .line 131
    const/4 v0, 0x4

    .line 132
    invoke-direct {v13, v6, v0, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 133
    .line 134
    .line 135
    move-object v6, v14

    .line 136
    new-instance v14, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 137
    .line 138
    move-object/from16 v21, v1

    .line 139
    .line 140
    invoke-static/range {v19 .. v19}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    invoke-direct {v14, v1, v0, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 145
    .line 146
    .line 147
    move-object v0, v10

    .line 148
    move-object v10, v15

    .line 149
    new-instance v15, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 150
    .line 151
    invoke-static/range {v19 .. v19}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    move-object/from16 v22, v0

    .line 156
    .line 157
    const/4 v0, 0x6

    .line 158
    invoke-direct {v15, v1, v0, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 159
    .line 160
    .line 161
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 162
    .line 163
    invoke-static/range {v19 .. v19}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;

    .line 168
    .line 169
    move-object/from16 v23, v2

    .line 170
    .line 171
    const/4 v2, 0x0

    .line 172
    invoke-direct {v1, v5, v2, v0, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 173
    .line 174
    .line 175
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 176
    .line 177
    invoke-static/range {v19 .. v19}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    move-object/from16 v18, v1

    .line 182
    .line 183
    const/4 v1, 0x1

    .line 184
    invoke-direct {v2, v5, v1, v0, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 185
    .line 186
    .line 187
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 188
    .line 189
    invoke-static/range {v19 .. v19}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 190
    .line 191
    .line 192
    move-result-object v5

    .line 193
    move-object/from16 v16, v2

    .line 194
    .line 195
    const/4 v2, 0x2

    .line 196
    invoke-direct {v1, v5, v2, v0, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 197
    .line 198
    .line 199
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 200
    .line 201
    invoke-static/range {v19 .. v19}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 202
    .line 203
    .line 204
    move-result-object v5

    .line 205
    move-object/from16 p0, v1

    .line 206
    .line 207
    const/4 v1, 0x3

    .line 208
    invoke-direct {v2, v5, v1, v0, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 209
    .line 210
    .line 211
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 212
    .line 213
    invoke-static/range {v19 .. v19}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 214
    .line 215
    .line 216
    move-result-object v5

    .line 217
    move-object/from16 v19, v2

    .line 218
    .line 219
    const/4 v2, 0x6

    .line 220
    invoke-direct {v1, v5, v2, v0, v7}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 221
    .line 222
    .line 223
    move-object/from16 v17, v16

    .line 224
    .line 225
    move-object/from16 v16, v18

    .line 226
    .line 227
    move-object/from16 v5, v20

    .line 228
    .line 229
    move-object/from16 v7, v22

    .line 230
    .line 231
    move-object/from16 v2, v23

    .line 232
    .line 233
    move-object/from16 v18, p0

    .line 234
    .line 235
    move-object/from16 v20, v1

    .line 236
    .line 237
    move-object/from16 v1, v21

    .line 238
    .line 239
    filled-new-array/range {v1 .. v20}, [Ltechnology/cariad/cat/genx/protocol/Address;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    return-object v0
.end method

.method public static final b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 7
    .line 8
    const/16 v0, 0x41

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    const/16 v2, 0x52

    .line 12
    .line 13
    const/16 v3, 0x50

    .line 14
    .line 15
    invoke-direct {p0, v2, v3, v0, v1}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method public static final c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 7
    .line 8
    const/16 v0, 0x40

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    const/16 v2, 0x52

    .line 12
    .line 13
    const/16 v3, 0x50

    .line 14
    .line 15
    invoke-direct {p0, v2, v3, v0, v1}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method
