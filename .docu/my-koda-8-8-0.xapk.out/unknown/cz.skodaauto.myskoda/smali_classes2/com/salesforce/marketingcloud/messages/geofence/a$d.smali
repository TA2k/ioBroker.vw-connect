.class Lcom/salesforce/marketingcloud/messages/geofence/a$d;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/geofence/a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->c:Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

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
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/j;->d(I)Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/j;->f(I)I

    .line 15
    .line 16
    .line 17
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 18
    .line 19
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 26
    .line 27
    iget-object v4, v4, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 28
    .line 29
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->c:Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

    .line 34
    .line 35
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->fences()Ljava/util/List;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-nez v5, :cond_4

    .line 44
    .line 45
    new-instance v5, Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 48
    .line 49
    .line 50
    iget-object v6, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->c:Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;

    .line 51
    .line 52
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->fences()Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object v6

    .line 56
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    :cond_0
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    if-eqz v7, :cond_3

    .line 65
    .line 66
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v7

    .line 70
    check-cast v7, Lcom/salesforce/marketingcloud/messages/Region;

    .line 71
    .line 72
    :try_start_0
    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/messages/Region;->messages()Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object v8

    .line 76
    invoke-interface {v8}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v8

    .line 80
    const/4 v9, 0x0

    .line 81
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v10

    .line 85
    if-eqz v10, :cond_1

    .line 86
    .line 87
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v9

    .line 91
    check-cast v9, Lcom/salesforce/marketingcloud/messages/Message;

    .line 92
    .line 93
    invoke-static {v9, v3, v4}, Lcom/salesforce/marketingcloud/messages/b;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/storage/i;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 94
    .line 95
    .line 96
    invoke-interface {v3, v9, v4}, Lcom/salesforce/marketingcloud/storage/i;->a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 97
    .line 98
    .line 99
    move v9, v1

    .line 100
    goto :goto_1

    .line 101
    :catch_0
    move-exception v8

    .line 102
    goto :goto_2

    .line 103
    :cond_1
    if-eqz v9, :cond_0

    .line 104
    .line 105
    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    invoke-interface {v2, v8}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    if-nez v8, :cond_2

    .line 114
    .line 115
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    :cond_2
    invoke-interface {v0, v7, v4}, Lcom/salesforce/marketingcloud/storage/j;->a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/util/Crypto;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :goto_2
    sget-object v9, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 123
    .line 124
    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v7

    .line 128
    filled-new-array {v7}, [Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    const-string v10, "Unable to start monitoring geofence region: %s"

    .line 133
    .line 134
    invoke-static {v9, v8, v10, v7}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_3
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 143
    .line 144
    .line 145
    move-result v3

    .line 146
    if-eqz v3, :cond_4

    .line 147
    .line 148
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    check-cast v3, Lcom/salesforce/marketingcloud/messages/Region;

    .line 153
    .line 154
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 155
    .line 156
    iget-object v4, v4, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 157
    .line 158
    invoke-static {v3}, Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/location/b;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    filled-new-array {v3}, [Lcom/salesforce/marketingcloud/location/b;

    .line 163
    .line 164
    .line 165
    move-result-object v3

    .line 166
    invoke-virtual {v4, v3}, Lcom/salesforce/marketingcloud/location/f;->a([Lcom/salesforce/marketingcloud/location/b;)V

    .line 167
    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_4
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-nez v0, :cond_5

    .line 175
    .line 176
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 177
    .line 178
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 179
    .line 180
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/location/f;->a(Ljava/util/List;)V

    .line 181
    .line 182
    .line 183
    :cond_5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$d;->d:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 184
    .line 185
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 186
    .line 187
    invoke-virtual {p0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 188
    .line 189
    .line 190
    return-void
.end method
