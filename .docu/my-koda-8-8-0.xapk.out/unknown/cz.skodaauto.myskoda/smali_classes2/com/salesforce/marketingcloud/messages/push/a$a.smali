.class Lcom/salesforce/marketingcloud/messages/push/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/push/a;->f(Ljava/util/Map;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic b:Ljava/util/Map;

.field final synthetic c:Lcom/salesforce/marketingcloud/messages/push/a;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/push/a;Ljava/util/Map;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/messages/push/a;->a(Lcom/salesforce/marketingcloud/messages/push/a;)Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->l:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 10
    .line 11
    invoke-static {v2}, Lcom/salesforce/marketingcloud/messages/push/a;->h(Ljava/util/Map;)Landroid/os/Bundle;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 19
    .line 20
    invoke-static {v0}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/Map;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 28
    .line 29
    new-array v0, v1, [Ljava/lang/Object;

    .line 30
    .line 31
    const-string v1, "Sync handler push received."

    .line 32
    .line 33
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 38
    .line 39
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/push/a;->isPushEnabled()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_1

    .line 44
    .line 45
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 46
    .line 47
    new-array v0, v1, [Ljava/lang/Object;

    .line 48
    .line 49
    const-string v1, "Push Messaging is disabled.  Ignoring message."

    .line 50
    .line 51
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 56
    .line 57
    const-string v2, "content-available"

    .line 58
    .line 59
    invoke-interface {v0, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_2

    .line 64
    .line 65
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 66
    .line 67
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 68
    .line 69
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/messages/push/a;->d(Lcom/salesforce/marketingcloud/messages/push/a;Ljava/util/Map;)V

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 74
    .line 75
    const-string v2, "_c"

    .line 76
    .line 77
    invoke-interface {v0, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 84
    .line 85
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 86
    .line 87
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/messages/push/a;->e(Lcom/salesforce/marketingcloud/messages/push/a;Ljava/util/Map;)V

    .line 88
    .line 89
    .line 90
    return-void

    .line 91
    :cond_3
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/internal/CompressionUtility;->INSTANCE:Lcom/salesforce/marketingcloud/internal/CompressionUtility;

    .line 92
    .line 93
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 94
    .line 95
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/internal/CompressionUtility;->decompress(Ljava/util/Map;)Ljava/util/Map;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/j;->a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    if-eqz v2, :cond_4

    .line 116
    .line 117
    sget-object v2, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 118
    .line 119
    const-string v3, "Message (%s) was received but does not have an alert message."

    .line 120
    .line 121
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-static {v2, v3, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    return-void

    .line 133
    :catch_0
    move-exception v0

    .line 134
    goto :goto_0

    .line 135
    :catch_1
    move-exception v0

    .line 136
    goto :goto_1

    .line 137
    :cond_4
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 138
    .line 139
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/push/a;->t:Lcom/salesforce/marketingcloud/push/h;

    .line 140
    .line 141
    invoke-virtual {v2, v0}, Lcom/salesforce/marketingcloud/push/h;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 142
    .line 143
    .line 144
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 145
    .line 146
    invoke-static {v2}, Lcom/salesforce/marketingcloud/messages/push/a;->b(Lcom/salesforce/marketingcloud/messages/push/a;)Lcom/salesforce/marketingcloud/notifications/a;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    const/4 v3, 0x0

    .line 151
    invoke-virtual {v2, v0, v3}, Lcom/salesforce/marketingcloud/notifications/a;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Lcom/salesforce/marketingcloud/notifications/a$b;)V
    :try_end_0
    .catch Lcom/salesforce/marketingcloud/push/f; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 152
    .line 153
    .line 154
    goto :goto_2

    .line 155
    :goto_0
    sget-object v2, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 156
    .line 157
    new-array v1, v1, [Ljava/lang/Object;

    .line 158
    .line 159
    const-string v3, "Unable to show push notification"

    .line 160
    .line 161
    invoke-static {v2, v0, v3, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :goto_1
    sget-object v2, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 166
    .line 167
    new-array v1, v1, [Ljava/lang/Object;

    .line 168
    .line 169
    const-string v3, "Unable to decompress push message"

    .line 170
    .line 171
    invoke-static {v2, v0, v3, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 175
    .line 176
    const-string v2, "_m"

    .line 177
    .line 178
    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    check-cast v1, Ljava/lang/String;

    .line 183
    .line 184
    if-eqz v1, :cond_5

    .line 185
    .line 186
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 187
    .line 188
    invoke-static {v2}, Lcom/salesforce/marketingcloud/messages/push/a;->c(Lcom/salesforce/marketingcloud/messages/push/a;)Lcom/salesforce/marketingcloud/analytics/j;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-interface {v2, v0, v1}, Lcom/salesforce/marketingcloud/analytics/j;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    :cond_5
    :goto_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->c:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 196
    .line 197
    invoke-static {v0}, Lcom/salesforce/marketingcloud/messages/push/a;->c(Lcom/salesforce/marketingcloud/messages/push/a;)Lcom/salesforce/marketingcloud/analytics/j;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/push/a$a;->b:Ljava/util/Map;

    .line 202
    .line 203
    invoke-interface {v0, p0}, Lcom/salesforce/marketingcloud/analytics/j;->a(Ljava/util/Map;)V

    .line 204
    .line 205
    .line 206
    return-void
.end method
