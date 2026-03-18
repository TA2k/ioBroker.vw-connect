.class public final Lzq0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzq0/e;

.field public final synthetic f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;


# direct methods
.method public synthetic constructor <init>(Lzq0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;I)V
    .locals 0

    .line 1
    iput p3, p0, Lzq0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzq0/c;->e:Lzq0/e;

    .line 4
    .line 5
    iput-object p2, p0, Lzq0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget p2, p0, Lzq0/c;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lyq0/g;

    .line 7
    .line 8
    iget-object v4, p1, Lyq0/g;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v2, p1, Lyq0/g;->b:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v3, p0, Lzq0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 13
    .line 14
    invoke-static {v3}, Landroidx/lifecycle/v0;->g(Landroidx/lifecycle/x;)Landroidx/lifecycle/s;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    new-instance v0, Lzq0/a;

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    iget-object v1, p0, Lzq0/c;->e:Lzq0/e;

    .line 22
    .line 23
    invoke-direct/range {v0 .. v5}, Lzq0/a;-><init>(Lzq0/e;Ljava/lang/String;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    const/4 p0, 0x3

    .line 27
    const/4 p2, 0x0

    .line 28
    invoke-static {p1, p2, p2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    check-cast p1, Lyq0/k;

    .line 35
    .line 36
    iget-object v4, p1, Lyq0/k;->a:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v3, p0, Lzq0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 39
    .line 40
    invoke-static {v3}, Landroidx/lifecycle/v0;->g(Landroidx/lifecycle/x;)Landroidx/lifecycle/s;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    new-instance v0, Lvh/j;

    .line 45
    .line 46
    const/16 v1, 0xc

    .line 47
    .line 48
    iget-object v2, p0, Lzq0/c;->e:Lzq0/e;

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    invoke-direct/range {v0 .. v5}, Lvh/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 52
    .line 53
    .line 54
    const/4 p0, 0x3

    .line 55
    invoke-static {p1, v5, v5, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_1
    check-cast p1, Llx0/b0;

    .line 62
    .line 63
    iget-object p1, p0, Lzq0/c;->e:Lzq0/e;

    .line 64
    .line 65
    iget-object p1, p1, Lzq0/e;->b:Luq0/a;

    .line 66
    .line 67
    iget-object p0, p0, Lzq0/c;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 68
    .line 69
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 74
    .line 75
    invoke-static {p0}, Lq/l;->b(Landroid/content/Context;)Landroid/hardware/biometrics/BiometricManager;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    const/16 v1, 0x1d

    .line 80
    .line 81
    if-gt p2, v1, :cond_0

    .line 82
    .line 83
    new-instance p2, Ler/i;

    .line 84
    .line 85
    const/4 v2, 0x0

    .line 86
    invoke-direct {p2, p0, v2}, Ler/i;-><init>(Landroid/content/Context;Z)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    const/4 p2, 0x0

    .line 91
    :goto_0
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 92
    .line 93
    const/16 v3, 0x1e

    .line 94
    .line 95
    const-string v4, "BiometricManager"

    .line 96
    .line 97
    const/4 v5, 0x1

    .line 98
    const/16 v6, 0xb

    .line 99
    .line 100
    const-string v7, "Failure in canAuthenticate(). BiometricManager was null."

    .line 101
    .line 102
    const/16 v8, 0xff

    .line 103
    .line 104
    if-lt v2, v3, :cond_2

    .line 105
    .line 106
    if-nez v0, :cond_1

    .line 107
    .line 108
    invoke-static {v4, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    goto/16 :goto_3

    .line 112
    .line 113
    :cond_1
    invoke-static {v0, v8}, Lq/m;->a(Landroid/hardware/biometrics/BiometricManager;I)I

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    goto/16 :goto_3

    .line 118
    .line 119
    :cond_2
    invoke-static {v8}, Ljp/ge;->b(I)Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-nez v3, :cond_3

    .line 124
    .line 125
    const/4 v5, -0x2

    .line 126
    goto :goto_3

    .line 127
    :cond_3
    invoke-static {p0}, Lq/a0;->a(Landroid/content/Context;)Landroid/app/KeyguardManager;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    const/16 v9, 0xc

    .line 132
    .line 133
    if-eqz v3, :cond_a

    .line 134
    .line 135
    invoke-static {v8}, Ljp/ge;->a(I)Z

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    const/4 v8, 0x0

    .line 140
    if-eqz v3, :cond_6

    .line 141
    .line 142
    invoke-static {p0}, Lq/a0;->a(Landroid/content/Context;)Landroid/app/KeyguardManager;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    if-nez p0, :cond_4

    .line 147
    .line 148
    move p0, v8

    .line 149
    goto :goto_1

    .line 150
    :cond_4
    invoke-static {p0}, Lq/a0;->b(Landroid/app/KeyguardManager;)Z

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    :goto_1
    if-eqz p0, :cond_5

    .line 155
    .line 156
    :goto_2
    move v5, v8

    .line 157
    goto :goto_3

    .line 158
    :cond_5
    move v5, v6

    .line 159
    goto :goto_3

    .line 160
    :cond_6
    if-ne v2, v1, :cond_8

    .line 161
    .line 162
    if-nez v0, :cond_7

    .line 163
    .line 164
    invoke-static {v4, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 165
    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_7
    invoke-static {v0}, Lq/l;->a(Landroid/hardware/biometrics/BiometricManager;)I

    .line 169
    .line 170
    .line 171
    move-result v5

    .line 172
    goto :goto_3

    .line 173
    :cond_8
    if-nez p2, :cond_9

    .line 174
    .line 175
    const-string p0, "Failure in canAuthenticate(). FingerprintManager was null."

    .line 176
    .line 177
    invoke-static {v4, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 178
    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_9
    iget-object p0, p2, Ler/i;->d:Landroid/content/Context;

    .line 182
    .line 183
    invoke-static {p0}, Ler/i;->b(Landroid/content/Context;)Landroid/hardware/fingerprint/FingerprintManager;

    .line 184
    .line 185
    .line 186
    move-result-object p2

    .line 187
    if-eqz p2, :cond_a

    .line 188
    .line 189
    invoke-virtual {p2}, Landroid/hardware/fingerprint/FingerprintManager;->isHardwareDetected()Z

    .line 190
    .line 191
    .line 192
    move-result p2

    .line 193
    if-eqz p2, :cond_a

    .line 194
    .line 195
    invoke-static {p0}, Ler/i;->b(Landroid/content/Context;)Landroid/hardware/fingerprint/FingerprintManager;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    if-eqz p0, :cond_5

    .line 200
    .line 201
    invoke-virtual {p0}, Landroid/hardware/fingerprint/FingerprintManager;->hasEnrolledFingerprints()Z

    .line 202
    .line 203
    .line 204
    move-result p0

    .line 205
    if-eqz p0, :cond_5

    .line 206
    .line 207
    goto :goto_2

    .line 208
    :cond_a
    move v5, v9

    .line 209
    :goto_3
    if-eqz v5, :cond_c

    .line 210
    .line 211
    if-eq v5, v6, :cond_b

    .line 212
    .line 213
    sget-object p0, Lyq0/b;->a:Lyq0/b;

    .line 214
    .line 215
    goto :goto_4

    .line 216
    :cond_b
    sget-object p0, Lyq0/c;->a:Lyq0/c;

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_c
    sget-object p0, Lyq0/a;->a:Lyq0/a;

    .line 220
    .line 221
    :goto_4
    iget-object p1, p1, Luq0/a;->c:Lyy0/q1;

    .line 222
    .line 223
    invoke-virtual {p1, p0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 227
    .line 228
    return-object p0

    .line 229
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
