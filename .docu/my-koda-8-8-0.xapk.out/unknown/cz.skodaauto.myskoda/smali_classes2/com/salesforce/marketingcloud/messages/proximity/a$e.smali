.class Lcom/salesforce/marketingcloud/messages/proximity/a$e;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/proximity/a;->a(Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/proximity/a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->c:Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()V
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 10
    .line 11
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 18
    .line 19
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 20
    .line 21
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const/4 v3, 0x3

    .line 26
    invoke-interface {v1, v3, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-nez v4, :cond_0

    .line 35
    .line 36
    invoke-static {v2}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 37
    .line 38
    .line 39
    :cond_0
    invoke-interface {v1, v3}, Lcom/salesforce/marketingcloud/storage/j;->f(I)I

    .line 40
    .line 41
    .line 42
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 43
    .line 44
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 45
    .line 46
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->c:Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

    .line 51
    .line 52
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;->beacons()Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-nez v4, :cond_5

    .line 61
    .line 62
    new-instance v4, Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 65
    .line 66
    .line 67
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->c:Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;

    .line 68
    .line 69
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/proximity/ProximityMessageResponse;->beacons()Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    :cond_1
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    if-eqz v6, :cond_4

    .line 82
    .line 83
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    check-cast v6, Lcom/salesforce/marketingcloud/messages/Region;

    .line 88
    .line 89
    :try_start_0
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/messages/Region;->messages()Ljava/util/List;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    const/4 v8, 0x0

    .line 98
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v9

    .line 102
    if-eqz v9, :cond_2

    .line 103
    .line 104
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v8

    .line 108
    check-cast v8, Lcom/salesforce/marketingcloud/messages/Message;

    .line 109
    .line 110
    invoke-static {v8, v3, v0}, Lcom/salesforce/marketingcloud/messages/b;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/storage/i;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 111
    .line 112
    .line 113
    invoke-interface {v3, v8, v0}, Lcom/salesforce/marketingcloud/storage/i;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 114
    .line 115
    .line 116
    const/4 v8, 0x1

    .line 117
    goto :goto_1

    .line 118
    :catch_0
    move-exception v7

    .line 119
    goto :goto_2

    .line 120
    :cond_2
    if-eqz v8, :cond_1

    .line 121
    .line 122
    invoke-static {v2, v6}, Ljava/util/Collections;->binarySearch(Ljava/util/List;Ljava/lang/Object;)I

    .line 123
    .line 124
    .line 125
    move-result v7

    .line 126
    if-ltz v7, :cond_3

    .line 127
    .line 128
    invoke-interface {v2, v7}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    check-cast v7, Lcom/salesforce/marketingcloud/messages/Region;

    .line 133
    .line 134
    invoke-static {v7}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/messages/Region;)Z

    .line 135
    .line 136
    .line 137
    move-result v7

    .line 138
    invoke-static {v6, v7}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/messages/Region;Z)V

    .line 139
    .line 140
    .line 141
    :cond_3
    invoke-interface {v1, v6, v0}, Lcom/salesforce/marketingcloud/storage/j;->a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 142
    .line 143
    .line 144
    new-instance v7, Lcom/salesforce/marketingcloud/proximity/c;

    .line 145
    .line 146
    invoke-direct {v7, v6}, Lcom/salesforce/marketingcloud/proximity/c;-><init>(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 150
    .line 151
    .line 152
    goto :goto_0

    .line 153
    :goto_2
    sget-object v8, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 154
    .line 155
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v6

    .line 159
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    const-string v9, "Unable to start monitoring proximity region: %s"

    .line 164
    .line 165
    invoke-static {v8, v7, v9, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    goto :goto_0

    .line 169
    :cond_4
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 170
    .line 171
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    const-string v3, "Monitoring beacons from request [%s]"

    .line 176
    .line 177
    invoke-static {v0, v3, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 181
    .line 182
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    .line 183
    .line 184
    invoke-virtual {v0, v4}, Lcom/salesforce/marketingcloud/proximity/e;->a(Ljava/util/List;)V

    .line 185
    .line 186
    .line 187
    :cond_5
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    if-nez v0, :cond_7

    .line 192
    .line 193
    new-instance v0, Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 196
    .line 197
    .line 198
    move-result v1

    .line 199
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 200
    .line 201
    .line 202
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    if-eqz v2, :cond_6

    .line 211
    .line 212
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    check-cast v2, Lcom/salesforce/marketingcloud/messages/Region;

    .line 217
    .line 218
    new-instance v3, Lcom/salesforce/marketingcloud/proximity/c;

    .line 219
    .line 220
    invoke-direct {v3, v2}, Lcom/salesforce/marketingcloud/proximity/c;-><init>(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    goto :goto_3

    .line 227
    :cond_6
    sget-object v1, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 228
    .line 229
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v2

    .line 233
    const-string v3, "Unmonitoring beacons [%s]"

    .line 234
    .line 235
    invoke-static {v1, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$e;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 239
    .line 240
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/e;

    .line 241
    .line 242
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/proximity/e;->b(Ljava/util/List;)V

    .line 243
    .line 244
    .line 245
    :cond_7
    return-void
.end method
