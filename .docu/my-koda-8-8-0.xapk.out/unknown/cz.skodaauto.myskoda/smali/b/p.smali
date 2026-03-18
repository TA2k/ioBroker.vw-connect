.class public final synthetic Lb/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lb/p;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lb/p;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput p1, p0, Lb/p;->f:I

    .line 6
    .line 7
    iput-object p4, p0, Lb/p;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    .line 1
    iget v0, p0, Lb/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 9
    .line 10
    iget-object v1, p0, Lb/p;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lw7/j;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_2

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    check-cast v2, Lw7/l;

    .line 29
    .line 30
    iget-boolean v3, v2, Lw7/l;->d:Z

    .line 31
    .line 32
    if-nez v3, :cond_0

    .line 33
    .line 34
    const/4 v3, -0x1

    .line 35
    iget v4, p0, Lb/p;->f:I

    .line 36
    .line 37
    if-eq v4, v3, :cond_1

    .line 38
    .line 39
    iget-object v3, v2, Lw7/l;->b:Lb6/f;

    .line 40
    .line 41
    invoke-virtual {v3, v4}, Lb6/f;->h(I)V

    .line 42
    .line 43
    .line 44
    :cond_1
    const/4 v3, 0x1

    .line 45
    iput-boolean v3, v2, Lw7/l;->c:Z

    .line 46
    .line 47
    iget-object v2, v2, Lw7/l;->a:Ljava/lang/Object;

    .line 48
    .line 49
    invoke-interface {v1, v2}, Lw7/j;->invoke(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return-void

    .line 54
    :pswitch_0
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Lh0/m;

    .line 57
    .line 58
    iget-object v1, p0, Lb/p;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v1, Lh0/s;

    .line 61
    .line 62
    iget p0, p0, Lb/p;->f:I

    .line 63
    .line 64
    invoke-virtual {v0, p0, v1}, Lh0/m;->b(ILh0/s;)V

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :pswitch_1
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v0, Lh0/m;

    .line 71
    .line 72
    iget-object v1, p0, Lb/p;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Lpy/a;

    .line 75
    .line 76
    iget p0, p0, Lb/p;->f:I

    .line 77
    .line 78
    invoke-virtual {v0, p0, v1}, Lh0/m;->c(ILpy/a;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :pswitch_2
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lb0/d1;

    .line 85
    .line 86
    iget-object v0, v0, Lb0/d1;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Lia/c;

    .line 89
    .line 90
    iget v1, p0, Lb/p;->f:I

    .line 91
    .line 92
    iget-object p0, p0, Lb/p;->g:Ljava/lang/Object;

    .line 93
    .line 94
    invoke-interface {v0, v1, p0}, Lia/c;->n(ILjava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    return-void

    .line 98
    :pswitch_3
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v0, Lc2/k;

    .line 101
    .line 102
    iget-object v1, p0, Lb/p;->g:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v1, Ldx/l;

    .line 105
    .line 106
    const-string v2, "$updateType"

    .line 107
    .line 108
    iget p0, p0, Lb/p;->f:I

    .line 109
    .line 110
    invoke-static {p0, v2}, Lia/b;->q(ILjava/lang/String;)V

    .line 111
    .line 112
    .line 113
    const-string v2, "$result"

    .line 114
    .line 115
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, p0, v1}, Lc2/k;->y(ILdx/l;)V

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    :pswitch_4
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Lb/q;

    .line 125
    .line 126
    iget-object v1, p0, Lb/p;->g:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v1, Landroid/content/IntentSender$SendIntentException;

    .line 129
    .line 130
    new-instance v2, Landroid/content/Intent;

    .line 131
    .line 132
    invoke-direct {v2}, Landroid/content/Intent;-><init>()V

    .line 133
    .line 134
    .line 135
    const-string v3, "androidx.activity.result.contract.action.INTENT_SENDER_REQUEST"

    .line 136
    .line 137
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    const-string v3, "androidx.activity.result.contract.extra.SEND_INTENT_EXCEPTION"

    .line 142
    .line 143
    invoke-virtual {v2, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/io/Serializable;)Landroid/content/Intent;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    iget p0, p0, Lb/p;->f:I

    .line 148
    .line 149
    const/4 v2, 0x0

    .line 150
    invoke-virtual {v0, p0, v2, v1}, Le/h;->a(IILandroid/content/Intent;)Z

    .line 151
    .line 152
    .line 153
    return-void

    .line 154
    :pswitch_5
    iget-object v0, p0, Lb/p;->e:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v0, Lb/q;

    .line 157
    .line 158
    iget-object v1, p0, Lb/p;->g:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v1, Lbu/c;

    .line 161
    .line 162
    iget-object v1, v1, Lbu/c;->e:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v1, Ljava/io/Serializable;

    .line 165
    .line 166
    iget-object v2, v0, Le/h;->a:Ljava/util/LinkedHashMap;

    .line 167
    .line 168
    iget p0, p0, Lb/p;->f:I

    .line 169
    .line 170
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    invoke-virtual {v2, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    check-cast p0, Ljava/lang/String;

    .line 179
    .line 180
    if-nez p0, :cond_3

    .line 181
    .line 182
    goto :goto_2

    .line 183
    :cond_3
    iget-object v2, v0, Le/h;->e:Ljava/util/LinkedHashMap;

    .line 184
    .line 185
    invoke-virtual {v2, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    check-cast v2, Le/e;

    .line 190
    .line 191
    if-eqz v2, :cond_4

    .line 192
    .line 193
    iget-object v3, v2, Le/e;->a:Le/b;

    .line 194
    .line 195
    goto :goto_1

    .line 196
    :cond_4
    const/4 v3, 0x0

    .line 197
    :goto_1
    if-nez v3, :cond_5

    .line 198
    .line 199
    iget-object v2, v0, Le/h;->g:Landroid/os/Bundle;

    .line 200
    .line 201
    invoke-virtual {v2, p0}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    iget-object v0, v0, Le/h;->f:Ljava/util/LinkedHashMap;

    .line 205
    .line 206
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    goto :goto_2

    .line 210
    :cond_5
    iget-object v2, v2, Le/e;->a:Le/b;

    .line 211
    .line 212
    const-string v3, "null cannot be cast to non-null type androidx.activity.result.ActivityResultCallback<O of androidx.activity.result.ActivityResultRegistry.dispatchResult>"

    .line 213
    .line 214
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    iget-object v0, v0, Le/h;->d:Ljava/util/ArrayList;

    .line 218
    .line 219
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    if-eqz p0, :cond_6

    .line 224
    .line 225
    invoke-interface {v2, v1}, Le/b;->a(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    :cond_6
    :goto_2
    return-void

    .line 229
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
