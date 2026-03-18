.class public final Liq0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Liq0/e;


# direct methods
.method public synthetic constructor <init>(Liq0/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Liq0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Liq0/b;->e:Liq0/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p2, p0, Liq0/b;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/String;

    .line 7
    .line 8
    new-instance p2, Landroid/content/Intent;

    .line 9
    .line 10
    const-string v0, "android.intent.action.VIEW"

    .line 11
    .line 12
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p2, p1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Liq0/b;->e:Liq0/e;

    .line 23
    .line 24
    iget-object p0, p0, Liq0/e;->a:Landroid/content/Context;

    .line 25
    .line 26
    invoke-static {p2}, Liq0/e;->a(Landroid/content/Intent;)Landroid/content/Intent;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 37
    .line 38
    new-instance p2, Landroid/content/Intent;

    .line 39
    .line 40
    const-string v0, "android.intent.action.SEND"

    .line 41
    .line 42
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const-string v0, "text/x-uri"

    .line 46
    .line 47
    invoke-virtual {p2, v0}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 48
    .line 49
    .line 50
    const-string v0, "android.intent.extra.TEXT"

    .line 51
    .line 52
    invoke-virtual {p2, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 53
    .line 54
    .line 55
    invoke-static {p2}, Liq0/e;->a(Landroid/content/Intent;)Landroid/content/Intent;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iget-object p0, p0, Liq0/b;->e:Liq0/e;

    .line 60
    .line 61
    iget-object p0, p0, Liq0/e;->a:Landroid/content/Context;

    .line 62
    .line 63
    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 64
    .line 65
    .line 66
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_1
    check-cast p1, Ljava/lang/String;

    .line 70
    .line 71
    new-instance p2, Landroid/content/Intent;

    .line 72
    .line 73
    const-string v0, "android.intent.action.SEND"

    .line 74
    .line 75
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v0, "text/plain"

    .line 79
    .line 80
    invoke-virtual {p2, v0}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 81
    .line 82
    .line 83
    const-string v0, "android.intent.extra.TEXT"

    .line 84
    .line 85
    invoke-virtual {p2, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 86
    .line 87
    .line 88
    invoke-static {p2}, Liq0/e;->a(Landroid/content/Intent;)Landroid/content/Intent;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iget-object p0, p0, Liq0/b;->e:Liq0/e;

    .line 93
    .line 94
    iget-object p0, p0, Liq0/e;->a:Landroid/content/Context;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_2
    check-cast p1, Ljava/io/File;

    .line 103
    .line 104
    iget-object p0, p0, Liq0/b;->e:Liq0/e;

    .line 105
    .line 106
    iget-object p0, p0, Liq0/e;->a:Landroid/content/Context;

    .line 107
    .line 108
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p2

    .line 112
    new-instance v0, Ljava/lang/StringBuilder;

    .line 113
    .line 114
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string p2, ".export"

    .line 121
    .line 122
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p2

    .line 129
    invoke-static {p0, p2, p1}, Landroidx/core/content/FileProvider;->d(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    const-string p2, "getUriForFile(...)"

    .line 134
    .line 135
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    new-instance p2, Landroid/content/Intent;

    .line 139
    .line 140
    const-string v0, "android.intent.action.SEND"

    .line 141
    .line 142
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const-string v0, "image/png"

    .line 146
    .line 147
    invoke-virtual {p2, v0}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 148
    .line 149
    .line 150
    const/4 v0, 0x1

    .line 151
    invoke-virtual {p2, v0}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 152
    .line 153
    .line 154
    const-string v0, "android.intent.extra.STREAM"

    .line 155
    .line 156
    invoke-virtual {p2, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 157
    .line 158
    .line 159
    invoke-static {p2}, Liq0/e;->a(Landroid/content/Intent;)Landroid/content/Intent;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 164
    .line 165
    .line 166
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    return-object p0

    .line 169
    :pswitch_3
    check-cast p1, Ljava/io/File;

    .line 170
    .line 171
    iget-object p0, p0, Liq0/b;->e:Liq0/e;

    .line 172
    .line 173
    iget-object p0, p0, Liq0/e;->a:Landroid/content/Context;

    .line 174
    .line 175
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p2

    .line 179
    new-instance v0, Ljava/lang/StringBuilder;

    .line 180
    .line 181
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    const-string p2, ".export"

    .line 188
    .line 189
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 190
    .line 191
    .line 192
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p2

    .line 196
    invoke-static {p0, p2, p1}, Landroidx/core/content/FileProvider;->d(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    const-string p2, "getUriForFile(...)"

    .line 201
    .line 202
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    new-instance p2, Landroid/content/Intent;

    .line 206
    .line 207
    const-string v0, "android.intent.action.SEND"

    .line 208
    .line 209
    invoke-direct {p2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    const-string v0, "text/plain"

    .line 213
    .line 214
    invoke-virtual {p2, v0}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 215
    .line 216
    .line 217
    const/4 v0, 0x1

    .line 218
    invoke-virtual {p2, v0}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 219
    .line 220
    .line 221
    const-string v0, "android.intent.extra.STREAM"

    .line 222
    .line 223
    invoke-virtual {p2, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 224
    .line 225
    .line 226
    invoke-static {p2}, Liq0/e;->a(Landroid/content/Intent;)Landroid/content/Intent;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 231
    .line 232
    .line 233
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 234
    .line 235
    return-object p0

    .line 236
    nop

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
