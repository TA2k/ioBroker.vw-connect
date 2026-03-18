.class public abstract Lkj0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lly0/n;

.field public static final b:Ljava/util/List;

.field public static final c:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 34

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    const-string v1, "[a-zA-Z][\\w]{0,39}"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lkj0/d;->a:Lly0/n;

    .line 9
    .line 10
    const-string v32, "session_start_with_rollout"

    .line 11
    .line 12
    const-string v33, "user_engagement"

    .line 13
    .line 14
    const-string v2, "ad_activeview"

    .line 15
    .line 16
    const-string v3, "ad_click"

    .line 17
    .line 18
    const-string v4, "ad_exposure"

    .line 19
    .line 20
    const-string v5, "ad_impression"

    .line 21
    .line 22
    const-string v6, "ad_query"

    .line 23
    .line 24
    const-string v7, "ad_reward"

    .line 25
    .line 26
    const-string v8, "adunit_exposure"

    .line 27
    .line 28
    const-string v9, "app_background"

    .line 29
    .line 30
    const-string v10, "app_clear_data"

    .line 31
    .line 32
    const-string v11, "app_exception"

    .line 33
    .line 34
    const-string v12, "app_remove"

    .line 35
    .line 36
    const-string v13, "app_store_refund"

    .line 37
    .line 38
    const-string v14, "app_store_subscription_cancel"

    .line 39
    .line 40
    const-string v15, "app_store_subscription_convert"

    .line 41
    .line 42
    const-string v16, "app_store_subscription_renew"

    .line 43
    .line 44
    const-string v17, "app_update"

    .line 45
    .line 46
    const-string v18, "app_upgrade"

    .line 47
    .line 48
    const-string v19, "dynamic_link_app_open"

    .line 49
    .line 50
    const-string v20, "dynamic_link_app_update"

    .line 51
    .line 52
    const-string v21, "dynamic_link_first_open"

    .line 53
    .line 54
    const-string v22, "error"

    .line 55
    .line 56
    const-string v23, "first_open"

    .line 57
    .line 58
    const-string v24, "first_visit"

    .line 59
    .line 60
    const-string v25, "in_app_purchase"

    .line 61
    .line 62
    const-string v26, "notification_dismiss"

    .line 63
    .line 64
    const-string v27, "notification_foreground"

    .line 65
    .line 66
    const-string v28, "notification_open"

    .line 67
    .line 68
    const-string v29, "notification_receive"

    .line 69
    .line 70
    const-string v30, "os_update"

    .line 71
    .line 72
    const-string v31, "session_start"

    .line 73
    .line 74
    filled-new-array/range {v2 .. v33}, [Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    sput-object v0, Lkj0/d;->b:Ljava/util/List;

    .line 83
    .line 84
    const-string v0, "google_"

    .line 85
    .line 86
    const-string v1, "ga_"

    .line 87
    .line 88
    const-string v2, "firebase_"

    .line 89
    .line 90
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    sput-object v0, Lkj0/d;->c:Ljava/util/List;

    .line 99
    .line 100
    return-void
.end method

.method public static a(Lkj0/b;)V
    .locals 11

    .line 1
    invoke-interface {p0}, Lkj0/b;->getName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lkj0/d;->a:Lly0/n;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const-string v3, "\' does not match valid format!"

    .line 12
    .line 13
    const-string v4, "Event name \'"

    .line 14
    .line 15
    if-eqz v2, :cond_c

    .line 16
    .line 17
    sget-object v2, Lkj0/d;->b:Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {v2, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_b

    .line 24
    .line 25
    sget-object v2, Lkj0/d;->c:Ljava/util/List;

    .line 26
    .line 27
    check-cast v2, Ljava/lang/Iterable;

    .line 28
    .line 29
    instance-of v5, v2, Ljava/util/Collection;

    .line 30
    .line 31
    const/4 v6, 0x0

    .line 32
    const-string v7, "\' starts with reserved Firebase prefix!"

    .line 33
    .line 34
    if-eqz v5, :cond_0

    .line 35
    .line 36
    move-object v8, v2

    .line 37
    check-cast v8, Ljava/util/Collection;

    .line 38
    .line 39
    invoke-interface {v8}, Ljava/util/Collection;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v8

    .line 43
    if-eqz v8, :cond_0

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_0
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    :goto_0
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v9

    .line 54
    if-eqz v9, :cond_2

    .line 55
    .line 56
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v9

    .line 60
    check-cast v9, Ljava/lang/String;

    .line 61
    .line 62
    invoke-static {v0, v9, v6}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    if-nez v9, :cond_1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    new-instance p0, Lkj0/c;

    .line 70
    .line 71
    invoke-static {v4, v0, v7}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :cond_2
    :goto_1
    invoke-interface {p0}, Lkj0/b;->getParams()Ljava/util/Set;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    check-cast p0, Ljava/lang/Iterable;

    .line 84
    .line 85
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    :cond_3
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_a

    .line 94
    .line 95
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    check-cast v0, Llx0/l;

    .line 100
    .line 101
    iget-object v4, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v4, Ljava/lang/String;

    .line 104
    .line 105
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v0, Ljava/lang/String;

    .line 108
    .line 109
    invoke-virtual {v1, v4}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    const-string v9, "Event param name \'"

    .line 114
    .line 115
    if-eqz v8, :cond_9

    .line 116
    .line 117
    if-eqz v5, :cond_4

    .line 118
    .line 119
    move-object v8, v2

    .line 120
    check-cast v8, Ljava/util/Collection;

    .line 121
    .line 122
    invoke-interface {v8}, Ljava/util/Collection;->isEmpty()Z

    .line 123
    .line 124
    .line 125
    move-result v8

    .line 126
    if-eqz v8, :cond_4

    .line 127
    .line 128
    goto :goto_4

    .line 129
    :cond_4
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object v8

    .line 133
    :goto_3
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    if-eqz v10, :cond_6

    .line 138
    .line 139
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v10

    .line 143
    check-cast v10, Ljava/lang/String;

    .line 144
    .line 145
    invoke-static {v4, v10, v6}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 146
    .line 147
    .line 148
    move-result v10

    .line 149
    if-nez v10, :cond_5

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_5
    new-instance p0, Lkj0/c;

    .line 153
    .line 154
    invoke-static {v9, v4, v7}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_6
    :goto_4
    if-eqz v0, :cond_3

    .line 163
    .line 164
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    const-string v9, "Event param \'"

    .line 169
    .line 170
    if-nez v8, :cond_8

    .line 171
    .line 172
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    const/16 v8, 0x64

    .line 177
    .line 178
    if-gt v0, v8, :cond_7

    .line 179
    .line 180
    goto :goto_2

    .line 181
    :cond_7
    new-instance p0, Lkj0/c;

    .line 182
    .line 183
    const-string v0, "\' value is too long (max length is 100 chars)!"

    .line 184
    .line 185
    invoke-static {v9, v4, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw p0

    .line 193
    :cond_8
    new-instance p0, Lkj0/c;

    .line 194
    .line 195
    const-string v0, "\' value is blank!"

    .line 196
    .line 197
    invoke-static {v9, v4, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    throw p0

    .line 205
    :cond_9
    new-instance p0, Lkj0/c;

    .line 206
    .line 207
    invoke-static {v9, v4, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0

    .line 215
    :cond_a
    return-void

    .line 216
    :cond_b
    new-instance p0, Lkj0/c;

    .line 217
    .line 218
    const-string v1, "\' is reserved by Firebase!"

    .line 219
    .line 220
    invoke-static {v4, v0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    throw p0

    .line 228
    :cond_c
    new-instance p0, Lkj0/c;

    .line 229
    .line 230
    invoke-static {v4, v0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    throw p0
.end method
