.class public final Ltr/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lgt/b;

.field public b:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(Lgt/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltr/c;->a:Lgt/b;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-object p1, p0, Ltr/c;->b:Ljava/lang/Integer;

    .line 8
    .line 9
    return-void
.end method

.method public static a(Ljava/util/ArrayList;Ltr/b;)Z
    .locals 3

    .line 1
    iget-object v0, p1, Ltr/b;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-object p1, p1, Ltr/b;->b:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Ltr/b;

    .line 20
    .line 21
    iget-object v2, v1, Ltr/b;->a:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    iget-object v1, v1, Ltr/b;->b:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v1, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    return p0

    .line 39
    :cond_1
    const/4 p0, 0x0

    .line 40
    return p0
.end method


# virtual methods
.method public final b()Ljava/util/ArrayList;
    .locals 11

    .line 1
    iget-object p0, p0, Ltr/c;->a:Lgt/b;

    .line 2
    .line 3
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lwr/b;

    .line 8
    .line 9
    check-cast p0, Lwr/c;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    new-instance v0, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lwr/c;->a:Lro/f;

    .line 20
    .line 21
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lcom/google/android/gms/internal/measurement/k1;

    .line 24
    .line 25
    const-string v1, "frc"

    .line 26
    .line 27
    const-string v2, ""

    .line 28
    .line 29
    invoke-virtual {p0, v1, v2}, Lcom/google/android/gms/internal/measurement/k1;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_0

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Landroid/os/Bundle;

    .line 48
    .line 49
    sget-object v2, Lxr/a;->a:Lhr/k0;

    .line 50
    .line 51
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    new-instance v2, Lwr/a;

    .line 55
    .line 56
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 57
    .line 58
    .line 59
    const-string v3, "origin"

    .line 60
    .line 61
    const-class v4, Ljava/lang/String;

    .line 62
    .line 63
    const/4 v5, 0x0

    .line 64
    invoke-static {v1, v3, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    check-cast v3, Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iput-object v3, v2, Lwr/a;->a:Ljava/lang/String;

    .line 74
    .line 75
    const-string v3, "name"

    .line 76
    .line 77
    invoke-static {v1, v3, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    check-cast v3, Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iput-object v3, v2, Lwr/a;->b:Ljava/lang/String;

    .line 87
    .line 88
    const-string v3, "value"

    .line 89
    .line 90
    const-class v6, Ljava/lang/Object;

    .line 91
    .line 92
    invoke-static {v1, v3, v6, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    iput-object v3, v2, Lwr/a;->c:Ljava/lang/Object;

    .line 97
    .line 98
    const-string v3, "trigger_event_name"

    .line 99
    .line 100
    invoke-static {v1, v3, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    check-cast v3, Ljava/lang/String;

    .line 105
    .line 106
    iput-object v3, v2, Lwr/a;->d:Ljava/lang/String;

    .line 107
    .line 108
    const-wide/16 v6, 0x0

    .line 109
    .line 110
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    const-string v6, "trigger_timeout"

    .line 115
    .line 116
    const-class v7, Ljava/lang/Long;

    .line 117
    .line 118
    invoke-static {v1, v6, v7, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v6

    .line 122
    check-cast v6, Ljava/lang/Long;

    .line 123
    .line 124
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 125
    .line 126
    .line 127
    move-result-wide v8

    .line 128
    iput-wide v8, v2, Lwr/a;->e:J

    .line 129
    .line 130
    const-string v6, "timed_out_event_name"

    .line 131
    .line 132
    invoke-static {v1, v6, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    check-cast v6, Ljava/lang/String;

    .line 137
    .line 138
    iput-object v6, v2, Lwr/a;->f:Ljava/lang/String;

    .line 139
    .line 140
    const-string v6, "timed_out_event_params"

    .line 141
    .line 142
    const-class v8, Landroid/os/Bundle;

    .line 143
    .line 144
    invoke-static {v1, v6, v8, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    check-cast v6, Landroid/os/Bundle;

    .line 149
    .line 150
    iput-object v6, v2, Lwr/a;->g:Landroid/os/Bundle;

    .line 151
    .line 152
    const-string v6, "triggered_event_name"

    .line 153
    .line 154
    invoke-static {v1, v6, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v6

    .line 158
    check-cast v6, Ljava/lang/String;

    .line 159
    .line 160
    iput-object v6, v2, Lwr/a;->h:Ljava/lang/String;

    .line 161
    .line 162
    const-string v6, "triggered_event_params"

    .line 163
    .line 164
    invoke-static {v1, v6, v8, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v6

    .line 168
    check-cast v6, Landroid/os/Bundle;

    .line 169
    .line 170
    iput-object v6, v2, Lwr/a;->i:Landroid/os/Bundle;

    .line 171
    .line 172
    const-string v6, "time_to_live"

    .line 173
    .line 174
    invoke-static {v1, v6, v7, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    check-cast v6, Ljava/lang/Long;

    .line 179
    .line 180
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 181
    .line 182
    .line 183
    move-result-wide v9

    .line 184
    iput-wide v9, v2, Lwr/a;->j:J

    .line 185
    .line 186
    const-string v6, "expired_event_name"

    .line 187
    .line 188
    invoke-static {v1, v6, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    check-cast v4, Ljava/lang/String;

    .line 193
    .line 194
    iput-object v4, v2, Lwr/a;->k:Ljava/lang/String;

    .line 195
    .line 196
    const-string v4, "expired_event_params"

    .line 197
    .line 198
    invoke-static {v1, v4, v8, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    check-cast v4, Landroid/os/Bundle;

    .line 203
    .line 204
    iput-object v4, v2, Lwr/a;->l:Landroid/os/Bundle;

    .line 205
    .line 206
    const-class v4, Ljava/lang/Boolean;

    .line 207
    .line 208
    sget-object v5, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 209
    .line 210
    const-string v6, "active"

    .line 211
    .line 212
    invoke-static {v1, v6, v4, v5}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    check-cast v4, Ljava/lang/Boolean;

    .line 217
    .line 218
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    iput-boolean v4, v2, Lwr/a;->n:Z

    .line 223
    .line 224
    const-string v4, "creation_timestamp"

    .line 225
    .line 226
    invoke-static {v1, v4, v7, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v4

    .line 230
    check-cast v4, Ljava/lang/Long;

    .line 231
    .line 232
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 233
    .line 234
    .line 235
    move-result-wide v4

    .line 236
    iput-wide v4, v2, Lwr/a;->m:J

    .line 237
    .line 238
    const-string v4, "triggered_timestamp"

    .line 239
    .line 240
    invoke-static {v1, v4, v7, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    check-cast v1, Ljava/lang/Long;

    .line 245
    .line 246
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 247
    .line 248
    .line 249
    move-result-wide v3

    .line 250
    iput-wide v3, v2, Lwr/a;->o:J

    .line 251
    .line 252
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    goto/16 :goto_0

    .line 256
    .line 257
    :cond_0
    return-object v0
.end method

.method public final c(Ljava/util/ArrayList;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ltr/c;->a:Lgt/b;

    .line 4
    .line 5
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    const-string v3, "The Analytics SDK is not available. Please check that the Analytics SDK is included in your app dependencies."

    .line 10
    .line 11
    if-eqz v2, :cond_22

    .line 12
    .line 13
    new-instance v2, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual/range {p1 .. p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    const-string v6, ""

    .line 27
    .line 28
    if-eqz v5, :cond_4

    .line 29
    .line 30
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    check-cast v5, Ljava/util/Map;

    .line 35
    .line 36
    sget-object v7, Ltr/b;->g:[Ljava/lang/String;

    .line 37
    .line 38
    const-string v7, "triggerEvent"

    .line 39
    .line 40
    new-instance v8, Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 43
    .line 44
    .line 45
    sget-object v9, Ltr/b;->g:[Ljava/lang/String;

    .line 46
    .line 47
    const/4 v10, 0x0

    .line 48
    :goto_1
    const/4 v11, 0x5

    .line 49
    if-ge v10, v11, :cond_1

    .line 50
    .line 51
    aget-object v11, v9, v10

    .line 52
    .line 53
    invoke-interface {v5, v11}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v12

    .line 57
    if-nez v12, :cond_0

    .line 58
    .line 59
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    :cond_0
    add-int/lit8 v10, v10, 0x1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    if-eqz v9, :cond_3

    .line 70
    .line 71
    :try_start_0
    sget-object v8, Ltr/b;->h:Ljava/text/SimpleDateFormat;

    .line 72
    .line 73
    const-string v9, "experimentStartTime"

    .line 74
    .line 75
    invoke-interface {v5, v9}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v9

    .line 79
    check-cast v9, Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {v8, v9}, Ljava/text/DateFormat;->parse(Ljava/lang/String;)Ljava/util/Date;

    .line 82
    .line 83
    .line 84
    move-result-object v14

    .line 85
    const-string v8, "triggerTimeoutMillis"

    .line 86
    .line 87
    invoke-interface {v5, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    check-cast v8, Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {v8}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 94
    .line 95
    .line 96
    move-result-wide v15

    .line 97
    const-string v8, "timeToLiveMillis"

    .line 98
    .line 99
    invoke-interface {v5, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    check-cast v8, Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {v8}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 106
    .line 107
    .line 108
    move-result-wide v17

    .line 109
    new-instance v10, Ltr/b;

    .line 110
    .line 111
    const-string v8, "experimentId"

    .line 112
    .line 113
    invoke-interface {v5, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    move-object v11, v8

    .line 118
    check-cast v11, Ljava/lang/String;

    .line 119
    .line 120
    const-string v8, "variantId"

    .line 121
    .line 122
    invoke-interface {v5, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v8

    .line 126
    move-object v12, v8

    .line 127
    check-cast v12, Ljava/lang/String;

    .line 128
    .line 129
    invoke-interface {v5, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v8

    .line 133
    if-eqz v8, :cond_2

    .line 134
    .line 135
    invoke-interface {v5, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v5

    .line 139
    move-object v6, v5

    .line 140
    check-cast v6, Ljava/lang/String;

    .line 141
    .line 142
    :cond_2
    move-object v13, v6

    .line 143
    invoke-direct/range {v10 .. v18}, Ltr/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;JJ)V
    :try_end_0
    .catch Ljava/text/ParseException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 144
    .line 145
    .line 146
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    goto :goto_0

    .line 150
    :catch_0
    move-exception v0

    .line 151
    new-instance v1, Ltr/a;

    .line 152
    .line 153
    const-string v2, "Could not process experiment: one of the durations could not be converted into a long."

    .line 154
    .line 155
    invoke-direct {v1, v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 156
    .line 157
    .line 158
    throw v1

    .line 159
    :catch_1
    move-exception v0

    .line 160
    new-instance v1, Ltr/a;

    .line 161
    .line 162
    const-string v2, "Could not process experiment: parsing experiment start time failed."

    .line 163
    .line 164
    invoke-direct {v1, v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 165
    .line 166
    .line 167
    throw v1

    .line 168
    :cond_3
    new-instance v0, Ltr/a;

    .line 169
    .line 170
    const-string v1, "The following keys are missing from the experiment info map: %s"

    .line 171
    .line 172
    filled-new-array {v8}, [Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    invoke-static {v1, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    throw v0

    .line 184
    :cond_4
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 185
    .line 186
    .line 187
    move-result v4

    .line 188
    const/4 v5, 0x0

    .line 189
    if-eqz v4, :cond_6

    .line 190
    .line 191
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    if-eqz v2, :cond_5

    .line 196
    .line 197
    invoke-virtual {v0}, Ltr/c;->b()Ljava/util/ArrayList;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 206
    .line 207
    .line 208
    move-result v2

    .line 209
    if-eqz v2, :cond_20

    .line 210
    .line 211
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    check-cast v2, Lwr/a;

    .line 216
    .line 217
    iget-object v2, v2, Lwr/a;->b:Ljava/lang/String;

    .line 218
    .line 219
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    check-cast v3, Lwr/b;

    .line 224
    .line 225
    check-cast v3, Lwr/c;

    .line 226
    .line 227
    iget-object v3, v3, Lwr/c;->a:Lro/f;

    .line 228
    .line 229
    iget-object v3, v3, Lro/f;->e:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v3, Lcom/google/android/gms/internal/measurement/k1;

    .line 232
    .line 233
    new-instance v4, Lcom/google/android/gms/internal/measurement/z0;

    .line 234
    .line 235
    invoke-direct {v4, v3, v2, v5, v5}, Lcom/google/android/gms/internal/measurement/z0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v3, v4}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 239
    .line 240
    .line 241
    goto :goto_2

    .line 242
    :cond_5
    new-instance v0, Ltr/a;

    .line 243
    .line 244
    invoke-direct {v0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw v0

    .line 248
    :cond_6
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    if-eqz v4, :cond_21

    .line 253
    .line 254
    invoke-virtual {v0}, Ltr/c;->b()Ljava/util/ArrayList;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    new-instance v4, Ljava/util/ArrayList;

    .line 259
    .line 260
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 264
    .line 265
    .line 266
    move-result-object v3

    .line 267
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 268
    .line 269
    .line 270
    move-result v7

    .line 271
    if-eqz v7, :cond_8

    .line 272
    .line 273
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v7

    .line 277
    check-cast v7, Lwr/a;

    .line 278
    .line 279
    sget-object v8, Ltr/b;->g:[Ljava/lang/String;

    .line 280
    .line 281
    iget-object v8, v7, Lwr/a;->d:Ljava/lang/String;

    .line 282
    .line 283
    if-eqz v8, :cond_7

    .line 284
    .line 285
    move-object v12, v8

    .line 286
    goto :goto_4

    .line 287
    :cond_7
    move-object v12, v6

    .line 288
    :goto_4
    new-instance v9, Ltr/b;

    .line 289
    .line 290
    iget-object v10, v7, Lwr/a;->b:Ljava/lang/String;

    .line 291
    .line 292
    iget-object v8, v7, Lwr/a;->c:Ljava/lang/Object;

    .line 293
    .line 294
    invoke-static {v8}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v11

    .line 298
    new-instance v13, Ljava/util/Date;

    .line 299
    .line 300
    iget-wide v14, v7, Lwr/a;->m:J

    .line 301
    .line 302
    invoke-direct {v13, v14, v15}, Ljava/util/Date;-><init>(J)V

    .line 303
    .line 304
    .line 305
    iget-wide v14, v7, Lwr/a;->e:J

    .line 306
    .line 307
    iget-wide v7, v7, Lwr/a;->j:J

    .line 308
    .line 309
    move-wide/from16 v16, v7

    .line 310
    .line 311
    invoke-direct/range {v9 .. v17}, Ltr/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;JJ)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v4, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 315
    .line 316
    .line 317
    goto :goto_3

    .line 318
    :cond_8
    new-instance v3, Ljava/util/ArrayList;

    .line 319
    .line 320
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 321
    .line 322
    .line 323
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 324
    .line 325
    .line 326
    move-result-object v6

    .line 327
    :cond_9
    :goto_5
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 328
    .line 329
    .line 330
    move-result v7

    .line 331
    if-eqz v7, :cond_a

    .line 332
    .line 333
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v7

    .line 337
    check-cast v7, Ltr/b;

    .line 338
    .line 339
    invoke-static {v2, v7}, Ltr/c;->a(Ljava/util/ArrayList;Ltr/b;)Z

    .line 340
    .line 341
    .line 342
    move-result v8

    .line 343
    if-nez v8, :cond_9

    .line 344
    .line 345
    invoke-virtual {v7}, Ltr/b;->a()Lwr/a;

    .line 346
    .line 347
    .line 348
    move-result-object v7

    .line 349
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 350
    .line 351
    .line 352
    goto :goto_5

    .line 353
    :cond_a
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 354
    .line 355
    .line 356
    move-result-object v3

    .line 357
    :goto_6
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 358
    .line 359
    .line 360
    move-result v6

    .line 361
    if-eqz v6, :cond_b

    .line 362
    .line 363
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v6

    .line 367
    check-cast v6, Lwr/a;

    .line 368
    .line 369
    iget-object v6, v6, Lwr/a;->b:Ljava/lang/String;

    .line 370
    .line 371
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v7

    .line 375
    check-cast v7, Lwr/b;

    .line 376
    .line 377
    check-cast v7, Lwr/c;

    .line 378
    .line 379
    iget-object v7, v7, Lwr/c;->a:Lro/f;

    .line 380
    .line 381
    iget-object v7, v7, Lro/f;->e:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v7, Lcom/google/android/gms/internal/measurement/k1;

    .line 384
    .line 385
    new-instance v8, Lcom/google/android/gms/internal/measurement/z0;

    .line 386
    .line 387
    invoke-direct {v8, v7, v6, v5, v5}, Lcom/google/android/gms/internal/measurement/z0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {v7, v8}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 391
    .line 392
    .line 393
    goto :goto_6

    .line 394
    :cond_b
    new-instance v3, Ljava/util/ArrayList;

    .line 395
    .line 396
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 400
    .line 401
    .line 402
    move-result-object v2

    .line 403
    :cond_c
    :goto_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 404
    .line 405
    .line 406
    move-result v6

    .line 407
    if-eqz v6, :cond_d

    .line 408
    .line 409
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 410
    .line 411
    .line 412
    move-result-object v6

    .line 413
    check-cast v6, Ltr/b;

    .line 414
    .line 415
    invoke-static {v4, v6}, Ltr/c;->a(Ljava/util/ArrayList;Ltr/b;)Z

    .line 416
    .line 417
    .line 418
    move-result v7

    .line 419
    if-nez v7, :cond_c

    .line 420
    .line 421
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 422
    .line 423
    .line 424
    goto :goto_7

    .line 425
    :cond_d
    new-instance v2, Ljava/util/ArrayDeque;

    .line 426
    .line 427
    invoke-virtual {v0}, Ltr/c;->b()Ljava/util/ArrayList;

    .line 428
    .line 429
    .line 430
    move-result-object v4

    .line 431
    invoke-direct {v2, v4}, Ljava/util/ArrayDeque;-><init>(Ljava/util/Collection;)V

    .line 432
    .line 433
    .line 434
    iget-object v4, v0, Ltr/c;->b:Ljava/lang/Integer;

    .line 435
    .line 436
    if-nez v4, :cond_e

    .line 437
    .line 438
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    move-result-object v4

    .line 442
    check-cast v4, Lwr/b;

    .line 443
    .line 444
    check-cast v4, Lwr/c;

    .line 445
    .line 446
    iget-object v4, v4, Lwr/c;->a:Lro/f;

    .line 447
    .line 448
    iget-object v4, v4, Lro/f;->e:Ljava/lang/Object;

    .line 449
    .line 450
    check-cast v4, Lcom/google/android/gms/internal/measurement/k1;

    .line 451
    .line 452
    const-string v6, "frc"

    .line 453
    .line 454
    invoke-virtual {v4, v6}, Lcom/google/android/gms/internal/measurement/k1;->b(Ljava/lang/String;)I

    .line 455
    .line 456
    .line 457
    move-result v4

    .line 458
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    iput-object v4, v0, Ltr/c;->b:Ljava/lang/Integer;

    .line 463
    .line 464
    :cond_e
    iget-object v0, v0, Ltr/c;->b:Ljava/lang/Integer;

    .line 465
    .line 466
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 467
    .line 468
    .line 469
    move-result v4

    .line 470
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 471
    .line 472
    .line 473
    move-result-object v3

    .line 474
    :goto_8
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 475
    .line 476
    .line 477
    move-result v0

    .line 478
    if-eqz v0, :cond_20

    .line 479
    .line 480
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    check-cast v0, Ltr/b;

    .line 485
    .line 486
    :goto_9
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->size()I

    .line 487
    .line 488
    .line 489
    move-result v6

    .line 490
    if-lt v6, v4, :cond_f

    .line 491
    .line 492
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->pollFirst()Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v6

    .line 496
    check-cast v6, Lwr/a;

    .line 497
    .line 498
    iget-object v6, v6, Lwr/a;->b:Ljava/lang/String;

    .line 499
    .line 500
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v7

    .line 504
    check-cast v7, Lwr/b;

    .line 505
    .line 506
    check-cast v7, Lwr/c;

    .line 507
    .line 508
    iget-object v7, v7, Lwr/c;->a:Lro/f;

    .line 509
    .line 510
    iget-object v7, v7, Lro/f;->e:Ljava/lang/Object;

    .line 511
    .line 512
    check-cast v7, Lcom/google/android/gms/internal/measurement/k1;

    .line 513
    .line 514
    new-instance v8, Lcom/google/android/gms/internal/measurement/z0;

    .line 515
    .line 516
    invoke-direct {v8, v7, v6, v5, v5}, Lcom/google/android/gms/internal/measurement/z0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 517
    .line 518
    .line 519
    invoke-virtual {v7, v8}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 520
    .line 521
    .line 522
    goto :goto_9

    .line 523
    :cond_f
    invoke-virtual {v0}, Ltr/b;->a()Lwr/a;

    .line 524
    .line 525
    .line 526
    move-result-object v6

    .line 527
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object v0

    .line 531
    check-cast v0, Lwr/b;

    .line 532
    .line 533
    move-object v7, v0

    .line 534
    check-cast v7, Lwr/c;

    .line 535
    .line 536
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 537
    .line 538
    .line 539
    sget-object v0, Lxr/a;->a:Lhr/k0;

    .line 540
    .line 541
    iget-object v8, v6, Lwr/a;->a:Ljava/lang/String;

    .line 542
    .line 543
    invoke-virtual {v8}, Ljava/lang/String;->isEmpty()Z

    .line 544
    .line 545
    .line 546
    move-result v0

    .line 547
    if-nez v0, :cond_1f

    .line 548
    .line 549
    iget-object v0, v6, Lwr/a;->c:Ljava/lang/Object;

    .line 550
    .line 551
    if-eqz v0, :cond_12

    .line 552
    .line 553
    :try_start_1
    new-instance v9, Ljava/io/ByteArrayOutputStream;

    .line 554
    .line 555
    invoke-direct {v9}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 556
    .line 557
    .line 558
    new-instance v10, Ljava/io/ObjectOutputStream;

    .line 559
    .line 560
    invoke-direct {v10, v9}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 561
    .line 562
    .line 563
    :try_start_2
    invoke-virtual {v10, v0}, Ljava/io/ObjectOutputStream;->writeObject(Ljava/lang/Object;)V

    .line 564
    .line 565
    .line 566
    invoke-virtual {v10}, Ljava/io/ObjectOutputStream;->flush()V

    .line 567
    .line 568
    .line 569
    new-instance v11, Ljava/io/ObjectInputStream;

    .line 570
    .line 571
    new-instance v0, Ljava/io/ByteArrayInputStream;

    .line 572
    .line 573
    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 574
    .line 575
    .line 576
    move-result-object v9

    .line 577
    invoke-direct {v0, v9}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 578
    .line 579
    .line 580
    invoke-direct {v11, v0}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 581
    .line 582
    .line 583
    :try_start_3
    invoke-virtual {v11}, Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;

    .line 584
    .line 585
    .line 586
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 587
    :try_start_4
    invoke-virtual {v10}, Ljava/io/ObjectOutputStream;->close()V

    .line 588
    .line 589
    .line 590
    invoke-virtual {v11}, Ljava/io/ObjectInputStream;->close()V

    .line 591
    .line 592
    .line 593
    goto :goto_b

    .line 594
    :catchall_0
    move-exception v0

    .line 595
    goto :goto_a

    .line 596
    :catchall_1
    move-exception v0

    .line 597
    move-object v11, v5

    .line 598
    goto :goto_a

    .line 599
    :catchall_2
    move-exception v0

    .line 600
    move-object v10, v5

    .line 601
    move-object v11, v10

    .line 602
    :goto_a
    if-eqz v10, :cond_10

    .line 603
    .line 604
    invoke-virtual {v10}, Ljava/io/ObjectOutputStream;->close()V

    .line 605
    .line 606
    .line 607
    :cond_10
    if-eqz v11, :cond_11

    .line 608
    .line 609
    invoke-virtual {v11}, Ljava/io/ObjectInputStream;->close()V

    .line 610
    .line 611
    .line 612
    :cond_11
    throw v0
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_2
    .catch Ljava/lang/ClassNotFoundException; {:try_start_4 .. :try_end_4} :catch_2

    .line 613
    :catch_2
    move-object v0, v5

    .line 614
    :goto_b
    if-eqz v0, :cond_1f

    .line 615
    .line 616
    :cond_12
    invoke-static {v8}, Lxr/a;->a(Ljava/lang/String;)Z

    .line 617
    .line 618
    .line 619
    move-result v0

    .line 620
    if-eqz v0, :cond_1f

    .line 621
    .line 622
    iget-object v0, v6, Lwr/a;->b:Ljava/lang/String;

    .line 623
    .line 624
    invoke-static {v8, v0}, Lxr/a;->c(Ljava/lang/String;Ljava/lang/String;)Z

    .line 625
    .line 626
    .line 627
    move-result v0

    .line 628
    if-eqz v0, :cond_1f

    .line 629
    .line 630
    iget-object v0, v6, Lwr/a;->k:Ljava/lang/String;

    .line 631
    .line 632
    if-eqz v0, :cond_13

    .line 633
    .line 634
    iget-object v9, v6, Lwr/a;->l:Landroid/os/Bundle;

    .line 635
    .line 636
    invoke-static {v0, v9}, Lxr/a;->b(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 637
    .line 638
    .line 639
    move-result v0

    .line 640
    if-eqz v0, :cond_1f

    .line 641
    .line 642
    iget-object v0, v6, Lwr/a;->k:Ljava/lang/String;

    .line 643
    .line 644
    iget-object v9, v6, Lwr/a;->l:Landroid/os/Bundle;

    .line 645
    .line 646
    invoke-static {v8, v0, v9}, Lxr/a;->d(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 647
    .line 648
    .line 649
    move-result v0

    .line 650
    if-eqz v0, :cond_1f

    .line 651
    .line 652
    :cond_13
    iget-object v0, v6, Lwr/a;->h:Ljava/lang/String;

    .line 653
    .line 654
    if-eqz v0, :cond_14

    .line 655
    .line 656
    iget-object v9, v6, Lwr/a;->i:Landroid/os/Bundle;

    .line 657
    .line 658
    invoke-static {v0, v9}, Lxr/a;->b(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 659
    .line 660
    .line 661
    move-result v0

    .line 662
    if-eqz v0, :cond_1f

    .line 663
    .line 664
    iget-object v0, v6, Lwr/a;->h:Ljava/lang/String;

    .line 665
    .line 666
    iget-object v9, v6, Lwr/a;->i:Landroid/os/Bundle;

    .line 667
    .line 668
    invoke-static {v8, v0, v9}, Lxr/a;->d(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 669
    .line 670
    .line 671
    move-result v0

    .line 672
    if-eqz v0, :cond_1f

    .line 673
    .line 674
    :cond_14
    iget-object v0, v6, Lwr/a;->f:Ljava/lang/String;

    .line 675
    .line 676
    if-eqz v0, :cond_15

    .line 677
    .line 678
    iget-object v9, v6, Lwr/a;->g:Landroid/os/Bundle;

    .line 679
    .line 680
    invoke-static {v0, v9}, Lxr/a;->b(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 681
    .line 682
    .line 683
    move-result v0

    .line 684
    if-eqz v0, :cond_1f

    .line 685
    .line 686
    iget-object v0, v6, Lwr/a;->f:Ljava/lang/String;

    .line 687
    .line 688
    iget-object v9, v6, Lwr/a;->g:Landroid/os/Bundle;

    .line 689
    .line 690
    invoke-static {v8, v0, v9}, Lxr/a;->d(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 691
    .line 692
    .line 693
    move-result v0

    .line 694
    if-eqz v0, :cond_1f

    .line 695
    .line 696
    :cond_15
    iget-object v0, v7, Lwr/c;->a:Lro/f;

    .line 697
    .line 698
    new-instance v7, Landroid/os/Bundle;

    .line 699
    .line 700
    invoke-direct {v7}, Landroid/os/Bundle;-><init>()V

    .line 701
    .line 702
    .line 703
    iget-object v8, v6, Lwr/a;->a:Ljava/lang/String;

    .line 704
    .line 705
    const-string v9, "origin"

    .line 706
    .line 707
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 708
    .line 709
    .line 710
    iget-object v8, v6, Lwr/a;->b:Ljava/lang/String;

    .line 711
    .line 712
    if-eqz v8, :cond_16

    .line 713
    .line 714
    const-string v9, "name"

    .line 715
    .line 716
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    :cond_16
    iget-object v8, v6, Lwr/a;->c:Ljava/lang/Object;

    .line 720
    .line 721
    if-eqz v8, :cond_17

    .line 722
    .line 723
    invoke-static {v7, v8}, Lvp/t1;->c(Landroid/os/Bundle;Ljava/lang/Object;)V

    .line 724
    .line 725
    .line 726
    :cond_17
    iget-object v8, v6, Lwr/a;->d:Ljava/lang/String;

    .line 727
    .line 728
    if-eqz v8, :cond_18

    .line 729
    .line 730
    const-string v9, "trigger_event_name"

    .line 731
    .line 732
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 733
    .line 734
    .line 735
    :cond_18
    iget-wide v8, v6, Lwr/a;->e:J

    .line 736
    .line 737
    const-string v10, "trigger_timeout"

    .line 738
    .line 739
    invoke-virtual {v7, v10, v8, v9}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 740
    .line 741
    .line 742
    iget-object v8, v6, Lwr/a;->f:Ljava/lang/String;

    .line 743
    .line 744
    if-eqz v8, :cond_19

    .line 745
    .line 746
    const-string v9, "timed_out_event_name"

    .line 747
    .line 748
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 749
    .line 750
    .line 751
    :cond_19
    iget-object v8, v6, Lwr/a;->g:Landroid/os/Bundle;

    .line 752
    .line 753
    if-eqz v8, :cond_1a

    .line 754
    .line 755
    const-string v9, "timed_out_event_params"

    .line 756
    .line 757
    invoke-virtual {v7, v9, v8}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 758
    .line 759
    .line 760
    :cond_1a
    iget-object v8, v6, Lwr/a;->h:Ljava/lang/String;

    .line 761
    .line 762
    if-eqz v8, :cond_1b

    .line 763
    .line 764
    const-string v9, "triggered_event_name"

    .line 765
    .line 766
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 767
    .line 768
    .line 769
    :cond_1b
    iget-object v8, v6, Lwr/a;->i:Landroid/os/Bundle;

    .line 770
    .line 771
    if-eqz v8, :cond_1c

    .line 772
    .line 773
    const-string v9, "triggered_event_params"

    .line 774
    .line 775
    invoke-virtual {v7, v9, v8}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 776
    .line 777
    .line 778
    :cond_1c
    iget-wide v8, v6, Lwr/a;->j:J

    .line 779
    .line 780
    const-string v10, "time_to_live"

    .line 781
    .line 782
    invoke-virtual {v7, v10, v8, v9}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 783
    .line 784
    .line 785
    iget-object v8, v6, Lwr/a;->k:Ljava/lang/String;

    .line 786
    .line 787
    if-eqz v8, :cond_1d

    .line 788
    .line 789
    const-string v9, "expired_event_name"

    .line 790
    .line 791
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 792
    .line 793
    .line 794
    :cond_1d
    iget-object v8, v6, Lwr/a;->l:Landroid/os/Bundle;

    .line 795
    .line 796
    if-eqz v8, :cond_1e

    .line 797
    .line 798
    const-string v9, "expired_event_params"

    .line 799
    .line 800
    invoke-virtual {v7, v9, v8}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 801
    .line 802
    .line 803
    :cond_1e
    iget-wide v8, v6, Lwr/a;->m:J

    .line 804
    .line 805
    const-string v10, "creation_timestamp"

    .line 806
    .line 807
    invoke-virtual {v7, v10, v8, v9}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 808
    .line 809
    .line 810
    iget-boolean v8, v6, Lwr/a;->n:Z

    .line 811
    .line 812
    const-string v9, "active"

    .line 813
    .line 814
    invoke-virtual {v7, v9, v8}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 815
    .line 816
    .line 817
    iget-wide v8, v6, Lwr/a;->o:J

    .line 818
    .line 819
    const-string v10, "triggered_timestamp"

    .line 820
    .line 821
    invoke-virtual {v7, v10, v8, v9}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 822
    .line 823
    .line 824
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 825
    .line 826
    check-cast v0, Lcom/google/android/gms/internal/measurement/k1;

    .line 827
    .line 828
    new-instance v8, Lcom/google/android/gms/internal/measurement/y0;

    .line 829
    .line 830
    invoke-direct {v8, v0, v7}, Lcom/google/android/gms/internal/measurement/y0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Landroid/os/Bundle;)V

    .line 831
    .line 832
    .line 833
    invoke-virtual {v0, v8}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 834
    .line 835
    .line 836
    :cond_1f
    invoke-virtual {v2, v6}, Ljava/util/ArrayDeque;->offer(Ljava/lang/Object;)Z

    .line 837
    .line 838
    .line 839
    goto/16 :goto_8

    .line 840
    .line 841
    :cond_20
    return-void

    .line 842
    :cond_21
    new-instance v0, Ltr/a;

    .line 843
    .line 844
    invoke-direct {v0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 845
    .line 846
    .line 847
    throw v0

    .line 848
    :cond_22
    new-instance v0, Ltr/a;

    .line 849
    .line 850
    invoke-direct {v0, v3}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 851
    .line 852
    .line 853
    throw v0
.end method
