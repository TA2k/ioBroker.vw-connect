.class Lcom/salesforce/marketingcloud/messages/geofence/a$b;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/geofence/a;->a(Ljava/lang/String;ILandroid/location/Location;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Ljava/lang/String;

.field final synthetic d:I

.field final synthetic e:Lcom/salesforce/marketingcloud/messages/geofence/a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/geofence/a;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->c:Ljava/lang/String;

    .line 4
    .line 5
    iput p5, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->d:I

    .line 6
    .line 7
    invoke-direct {p0, p2, p3}, Lcom/salesforce/marketingcloud/internal/i;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public a()V
    .locals 7

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->c:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 12
    .line 13
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const/4 v2, 0x0

    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    sget-object v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 27
    .line 28
    const-string v1, "Removing stale geofence from being monitored."

    .line 29
    .line 30
    new-array v2, v2, [Ljava/lang/Object;

    .line 31
    .line 32
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 36
    .line 37
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/geofence/a;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 38
    .line 39
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->c:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/location/f;->a(Ljava/util/List;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :catch_0
    move-exception v0

    .line 50
    goto :goto_2

    .line 51
    :cond_0
    iget v3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->d:I

    .line 52
    .line 53
    const/4 v4, 0x1

    .line 54
    if-ne v3, v4, :cond_1

    .line 55
    .line 56
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 57
    .line 58
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/geofence/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 59
    .line 60
    invoke-interface {v2, v1}, Lcom/salesforce/marketingcloud/messages/c$a;->b(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 61
    .line 62
    .line 63
    const/4 v2, 0x3

    .line 64
    goto :goto_0

    .line 65
    :cond_1
    const/4 v4, 0x2

    .line 66
    if-ne v3, v4, :cond_2

    .line 67
    .line 68
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 69
    .line 70
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/geofence/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 71
    .line 72
    invoke-interface {v2, v1}, Lcom/salesforce/marketingcloud/messages/c$a;->a(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 73
    .line 74
    .line 75
    const/4 v2, 0x4

    .line 76
    :cond_2
    :goto_0
    if-eqz v2, :cond_4

    .line 77
    .line 78
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    invoke-interface {v0, v3, v2}, Lcom/salesforce/marketingcloud/storage/j;->c(Ljava/lang/String;I)Ljava/util/List;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-nez v2, :cond_4

    .line 91
    .line 92
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 93
    .line 94
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 95
    .line 96
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 101
    .line 102
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/geofence/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 103
    .line 104
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    if-eqz v4, :cond_4

    .line 117
    .line 118
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    check-cast v4, Ljava/lang/String;

    .line 123
    .line 124
    invoke-interface {v2, v4, v3}, Lcom/salesforce/marketingcloud/storage/i;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Message;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    if-eqz v5, :cond_3

    .line 129
    .line 130
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->e:Lcom/salesforce/marketingcloud/messages/geofence/a;

    .line 131
    .line 132
    iget-object v4, v4, Lcom/salesforce/marketingcloud/messages/geofence/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 133
    .line 134
    invoke-interface {v4, v1, v5}, Lcom/salesforce/marketingcloud/messages/c$a;->a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/messages/Message;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_3
    sget-object v5, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 139
    .line 140
    const-string v6, "Message with id [%s] not found"

    .line 141
    .line 142
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    invoke-static {v5, v6, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 147
    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_4
    return-void

    .line 151
    :goto_2
    sget-object v1, Lcom/salesforce/marketingcloud/messages/geofence/a;->k:Ljava/lang/String;

    .line 152
    .line 153
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->c:Ljava/lang/String;

    .line 154
    .line 155
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/a$b;->d:I

    .line 156
    .line 157
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    filled-new-array {v2, p0}, [Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    const-string v2, "Geofence (%s - %d) was tripped, but failed to check for associated message"

    .line 166
    .line 167
    invoke-static {v1, v0, v2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    return-void
.end method
