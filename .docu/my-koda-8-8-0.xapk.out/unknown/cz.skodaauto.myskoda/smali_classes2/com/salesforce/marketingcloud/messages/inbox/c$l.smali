.class Lcom/salesforce/marketingcloud/messages/inbox/c$l;
.super Lcom/salesforce/marketingcloud/internal/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/messages/inbox/c;->b(Ljava/util/List;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic c:Ljava/util/List;

.field final synthetic d:Lcom/salesforce/marketingcloud/messages/inbox/c;


# direct methods
.method public varargs constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;Ljava/lang/String;[Ljava/lang/Object;Ljava/util/List;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->c:Ljava/util/List;

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
    .locals 9

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->l()Lcom/salesforce/marketingcloud/storage/f;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 10
    .line 11
    iget-object v1, v1, Lcom/salesforce/marketingcloud/messages/inbox/c;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->c:Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_b

    .line 24
    .line 25
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 26
    .line 27
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->c:Ljava/util/List;

    .line 28
    .line 29
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    :cond_0
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-eqz v4, :cond_a

    .line 38
    .line 39
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 44
    .line 45
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->getDeleted()Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-eqz v5, :cond_2

    .line 50
    .line 51
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_1

    .line 56
    .line 57
    new-instance v2, Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 60
    .line 61
    .line 62
    :cond_1
    iget-object v4, v4, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 63
    .line 64
    invoke-interface {v2, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    invoke-interface {v0, v5}, Lcom/salesforce/marketingcloud/storage/f;->f(Ljava/lang/String;)Lcom/salesforce/marketingcloud/storage/f$b;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    const/4 v6, 0x1

    .line 77
    if-eqz v5, :cond_9

    .line 78
    .line 79
    iget-object v7, v5, Lcom/salesforce/marketingcloud/storage/f$b;->b:Ljava/lang/String;

    .line 80
    .line 81
    if-nez v7, :cond_3

    .line 82
    .line 83
    iget-boolean v7, v5, Lcom/salesforce/marketingcloud/storage/f$b;->e:Z

    .line 84
    .line 85
    invoke-static {v4, v7}, Lcom/salesforce/marketingcloud/internal/d;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 86
    .line 87
    .line 88
    iget-boolean v7, v5, Lcom/salesforce/marketingcloud/storage/f$b;->d:Z

    .line 89
    .line 90
    invoke-static {v4, v7}, Lcom/salesforce/marketingcloud/internal/d;->c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    invoke-static {v4}, Lcom/salesforce/marketingcloud/internal/d;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v8

    .line 98
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    if-eqz v7, :cond_4

    .line 103
    .line 104
    iget-boolean v7, v5, Lcom/salesforce/marketingcloud/storage/f$b;->e:Z

    .line 105
    .line 106
    invoke-static {v4, v7}, Lcom/salesforce/marketingcloud/internal/d;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 107
    .line 108
    .line 109
    iget-boolean v7, v5, Lcom/salesforce/marketingcloud/storage/f$b;->d:Z

    .line 110
    .line 111
    invoke-static {v4, v7}, Lcom/salesforce/marketingcloud/internal/d;->c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 112
    .line 113
    .line 114
    iget-object v7, v5, Lcom/salesforce/marketingcloud/storage/f$b;->c:Ljava/util/Date;

    .line 115
    .line 116
    if-nez v7, :cond_5

    .line 117
    .line 118
    :cond_4
    :goto_1
    move v7, v6

    .line 119
    goto :goto_2

    .line 120
    :cond_5
    const/4 v7, 0x0

    .line 121
    :goto_2
    iget-boolean v8, v5, Lcom/salesforce/marketingcloud/storage/f$b;->f:Z

    .line 122
    .line 123
    invoke-static {v4, v8}, Lcom/salesforce/marketingcloud/internal/d;->b(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 124
    .line 125
    .line 126
    invoke-static {v4}, Lcom/salesforce/marketingcloud/internal/d;->c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)I

    .line 127
    .line 128
    .line 129
    move-result v8

    .line 130
    if-lez v8, :cond_6

    .line 131
    .line 132
    invoke-static {v4, v6}, Lcom/salesforce/marketingcloud/internal/d;->c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 133
    .line 134
    .line 135
    :cond_6
    iget-boolean v8, v5, Lcom/salesforce/marketingcloud/storage/f$b;->e:Z

    .line 136
    .line 137
    if-nez v8, :cond_7

    .line 138
    .line 139
    iget-boolean v5, v5, Lcom/salesforce/marketingcloud/storage/f$b;->d:Z

    .line 140
    .line 141
    if-eqz v5, :cond_8

    .line 142
    .line 143
    invoke-static {v4}, Lcom/salesforce/marketingcloud/internal/d;->c(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)I

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-nez v5, :cond_8

    .line 148
    .line 149
    :cond_7
    invoke-static {v4, v6}, Lcom/salesforce/marketingcloud/internal/d;->b(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Z)V

    .line 150
    .line 151
    .line 152
    :cond_8
    move v6, v7

    .line 153
    :cond_9
    invoke-interface {v0, v4, v1}, Lcom/salesforce/marketingcloud/storage/f;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 154
    .line 155
    .line 156
    if-eqz v6, :cond_0

    .line 157
    .line 158
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/inbox/c$l;->d:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 159
    .line 160
    iget-object v5, v5, Lcom/salesforce/marketingcloud/messages/inbox/c;->e:Lcom/salesforce/marketingcloud/analytics/g;

    .line 161
    .line 162
    invoke-interface {v5, v4}, Lcom/salesforce/marketingcloud/analytics/g;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 163
    .line 164
    .line 165
    goto/16 :goto_0

    .line 166
    .line 167
    :cond_a
    invoke-interface {v0, v2}, Lcom/salesforce/marketingcloud/storage/f;->a(Ljava/util/List;)I

    .line 168
    .line 169
    .line 170
    :cond_b
    new-instance v0, Landroid/os/Handler;

    .line 171
    .line 172
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 177
    .line 178
    .line 179
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/c$l$a;

    .line 180
    .line 181
    invoke-direct {v1, p0}, Lcom/salesforce/marketingcloud/messages/inbox/c$l$a;-><init>(Lcom/salesforce/marketingcloud/messages/inbox/c$l;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 185
    .line 186
    .line 187
    return-void
.end method
