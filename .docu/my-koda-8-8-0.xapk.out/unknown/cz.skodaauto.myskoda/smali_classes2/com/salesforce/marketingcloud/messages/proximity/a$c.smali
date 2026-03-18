.class Lcom/salesforce/marketingcloud/messages/proximity/a$c;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/proximity/a;->b(Lcom/salesforce/marketingcloud/proximity/c;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Lcom/salesforce/marketingcloud/proximity/c;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/proximity/a;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/proximity/a;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/proximity/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->c:Lcom/salesforce/marketingcloud/proximity/c;

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
    .locals 7

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->o()Lcom/salesforce/marketingcloud/storage/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->c:Lcom/salesforce/marketingcloud/proximity/c;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 16
    .line 17
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 18
    .line 19
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 30
    .line 31
    const-string v1, "BeaconRegion [%s] did not have matching Region in storage."

    .line 32
    .line 33
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->c:Lcom/salesforce/marketingcloud/proximity/c;

    .line 34
    .line 35
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-static {v0, v1, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :catch_0
    move-exception v0

    .line 44
    goto/16 :goto_1

    .line 45
    .line 46
    :cond_0
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/messages/Region;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    if-nez v2, :cond_3

    .line 51
    .line 52
    sget-object v2, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 53
    .line 54
    const-string v3, "Region [%s] was entered.  Will attempt to show associated message."

    .line 55
    .line 56
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    invoke-static {v2, v3, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    const/4 v2, 0x1

    .line 68
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/internal/l;->a(Lcom/salesforce/marketingcloud/messages/Region;Z)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    invoke-interface {v0, v3, v2}, Lcom/salesforce/marketingcloud/storage/j;->a(Ljava/lang/String;Z)V

    .line 76
    .line 77
    .line 78
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 79
    .line 80
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/proximity/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 81
    .line 82
    invoke-interface {v2, v1}, Lcom/salesforce/marketingcloud/messages/c$a;->b(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    const/4 v3, 0x5

    .line 90
    invoke-interface {v0, v2, v3}, Lcom/salesforce/marketingcloud/storage/j;->c(Ljava/lang/String;I)Ljava/util/List;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-nez v2, :cond_2

    .line 99
    .line 100
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 101
    .line 102
    iget-object v2, v2, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 103
    .line 104
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->n()Lcom/salesforce/marketingcloud/storage/i;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 109
    .line 110
    iget-object v3, v3, Lcom/salesforce/marketingcloud/messages/proximity/a;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 111
    .line 112
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 121
    .line 122
    .line 123
    move-result v4

    .line 124
    if-eqz v4, :cond_2

    .line 125
    .line 126
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    check-cast v4, Ljava/lang/String;

    .line 131
    .line 132
    invoke-interface {v2, v4, v3}, Lcom/salesforce/marketingcloud/storage/i;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Message;

    .line 133
    .line 134
    .line 135
    move-result-object v5

    .line 136
    if-eqz v5, :cond_1

    .line 137
    .line 138
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->d:Lcom/salesforce/marketingcloud/messages/proximity/a;

    .line 139
    .line 140
    iget-object v4, v4, Lcom/salesforce/marketingcloud/messages/proximity/a;->f:Lcom/salesforce/marketingcloud/messages/c$a;

    .line 141
    .line 142
    invoke-interface {v4, v1, v5}, Lcom/salesforce/marketingcloud/messages/c$a;->a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/messages/Message;)V

    .line 143
    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_1
    sget-object v5, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 147
    .line 148
    const-string v6, "Message with id [%s] not found"

    .line 149
    .line 150
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v4

    .line 154
    invoke-static {v5, v6, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_2
    return-void

    .line 159
    :cond_3
    sget-object v0, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 160
    .line 161
    const-string v2, "Ignoring entry event.  Already inside Region [%s]"

    .line 162
    .line 163
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 168
    .line 169
    .line 170
    return-void

    .line 171
    :goto_1
    sget-object v1, Lcom/salesforce/marketingcloud/messages/proximity/a;->j:Ljava/lang/String;

    .line 172
    .line 173
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/proximity/a$c;->c:Lcom/salesforce/marketingcloud/proximity/c;

    .line 174
    .line 175
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    const-string v2, "Proximity region (%s) was entered, but failed to check for associated message"

    .line 184
    .line 185
    invoke-static {v1, v0, v2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    return-void
.end method
