.class public final synthetic Leo0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Leo0/b;


# direct methods
.method public synthetic constructor <init>(Leo0/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Leo0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Leo0/a;->e:Leo0/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Leo0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lk21/a;

    .line 4
    .line 5
    check-cast p2, Lg21/a;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v0, "$this$scopedFactory"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "it"

    .line 16
    .line 17
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p2, Lfo0/c;

    .line 21
    .line 22
    iget-object p0, p0, Leo0/a;->e:Leo0/b;

    .line 23
    .line 24
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const-class v0, Ldo0/a;

    .line 31
    .line 32
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 33
    .line 34
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    const/4 v1, 0x0

    .line 39
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Ldo0/a;

    .line 44
    .line 45
    invoke-direct {p2, p0}, Lfo0/c;-><init>(Ldo0/a;)V

    .line 46
    .line 47
    .line 48
    return-object p2

    .line 49
    :pswitch_0
    const-string v0, "$this$scopedFactory"

    .line 50
    .line 51
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string v0, "it"

    .line 55
    .line 56
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance p2, Lfo0/d;

    .line 60
    .line 61
    iget-object p0, p0, Leo0/a;->e:Leo0/b;

    .line 62
    .line 63
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-class v0, Ldo0/a;

    .line 70
    .line 71
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 72
    .line 73
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Ldo0/a;

    .line 83
    .line 84
    invoke-direct {p2, p0}, Lfo0/d;-><init>(Ldo0/a;)V

    .line 85
    .line 86
    .line 87
    return-object p2

    .line 88
    :pswitch_1
    const-string v0, "$this$scopedFactory"

    .line 89
    .line 90
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    const-string v0, "it"

    .line 94
    .line 95
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    new-instance p2, Lfo0/b;

    .line 99
    .line 100
    iget-object p0, p0, Leo0/a;->e:Leo0/b;

    .line 101
    .line 102
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 103
    .line 104
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    const-class v0, Ldo0/a;

    .line 109
    .line 110
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 111
    .line 112
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    const/4 v1, 0x0

    .line 117
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Ldo0/a;

    .line 122
    .line 123
    invoke-direct {p2, p0}, Lfo0/b;-><init>(Ldo0/a;)V

    .line 124
    .line 125
    .line 126
    return-object p2

    .line 127
    :pswitch_2
    const-string v0, "$this$scopedFactory"

    .line 128
    .line 129
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    const-string v0, "it"

    .line 133
    .line 134
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    new-instance p2, Lfo0/a;

    .line 138
    .line 139
    iget-object p0, p0, Leo0/a;->e:Leo0/b;

    .line 140
    .line 141
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 142
    .line 143
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    const-class v0, Ldo0/a;

    .line 148
    .line 149
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 150
    .line 151
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    const/4 v1, 0x0

    .line 156
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    check-cast p0, Ldo0/a;

    .line 161
    .line 162
    invoke-direct {p2, p0}, Lfo0/a;-><init>(Ldo0/a;)V

    .line 163
    .line 164
    .line 165
    return-object p2

    .line 166
    :pswitch_3
    const-string v0, "$this$scopedViewModel"

    .line 167
    .line 168
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    const-string v0, "it"

    .line 172
    .line 173
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    new-instance p2, Lho0/b;

    .line 177
    .line 178
    iget-object p0, p0, Leo0/a;->e:Leo0/b;

    .line 179
    .line 180
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 187
    .line 188
    const-class v2, Lfo0/a;

    .line 189
    .line 190
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    const/4 v3, 0x0

    .line 195
    invoke-virtual {p1, v2, v0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    check-cast v0, Lfo0/a;

    .line 200
    .line 201
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    const-class v2, Lfo0/d;

    .line 206
    .line 207
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    invoke-virtual {p1, v1, p0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    check-cast p0, Lfo0/d;

    .line 216
    .line 217
    invoke-direct {p2, v0, p0}, Lho0/b;-><init>(Lfo0/a;Lfo0/d;)V

    .line 218
    .line 219
    .line 220
    return-object p2

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
