.class public final Lh40/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/f1;


# direct methods
.method public synthetic constructor <init>(Lh40/f1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/b1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/b1;->e:Lh40/f1;

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
    .locals 13

    .line 1
    iget p2, p0, Lh40/b1;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/e;

    .line 9
    .line 10
    iget-object p0, p0, Lh40/b1;->e:Lh40/f1;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    iget-object p2, p0, Lh40/f1;->r:Lbq0/s;

    .line 15
    .line 16
    check-cast p1, Lne0/e;

    .line 17
    .line 18
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Lcq0/n;

    .line 21
    .line 22
    invoke-virtual {p2, p1}, Lbq0/s;->a(Lcq0/n;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    move-object v0, p1

    .line 30
    check-cast v0, Lh40/e1;

    .line 31
    .line 32
    const/4 v11, 0x0

    .line 33
    const/16 v12, 0xbff

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    const/4 v2, 0x0

    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v6, 0x0

    .line 41
    const/4 v7, 0x0

    .line 42
    const/4 v8, 0x0

    .line 43
    const/4 v9, 0x0

    .line 44
    const/4 v10, 0x0

    .line 45
    invoke-static/range {v0 .. v12}, Lh40/e1;->a(Lh40/e1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;Ljava/lang/String;I)Lh40/e1;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    instance-of p1, p1, Lne0/c;

    .line 54
    .line 55
    if-eqz p1, :cond_1

    .line 56
    .line 57
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    move-object v0, p1

    .line 62
    check-cast v0, Lh40/e1;

    .line 63
    .line 64
    const/4 v11, 0x0

    .line 65
    const/16 v12, 0xbff

    .line 66
    .line 67
    const/4 v1, 0x0

    .line 68
    const/4 v2, 0x0

    .line 69
    const/4 v3, 0x0

    .line 70
    const/4 v4, 0x0

    .line 71
    const/4 v5, 0x0

    .line 72
    const/4 v6, 0x0

    .line 73
    const/4 v7, 0x0

    .line 74
    const/4 v8, 0x0

    .line 75
    const/4 v9, 0x0

    .line 76
    const/4 v10, 0x0

    .line 77
    invoke-static/range {v0 .. v12}, Lh40/e1;->a(Lh40/e1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;Ljava/lang/String;I)Lh40/e1;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 82
    .line 83
    .line 84
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 88
    .line 89
    iget-object p0, p0, Lh40/b1;->e:Lh40/f1;

    .line 90
    .line 91
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    move-object v0, p2

    .line 96
    check-cast v0, Lh40/e1;

    .line 97
    .line 98
    instance-of p2, p1, Lne0/e;

    .line 99
    .line 100
    const/4 v1, 0x0

    .line 101
    if-eqz p2, :cond_2

    .line 102
    .line 103
    check-cast p1, Lne0/e;

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_2
    move-object p1, v1

    .line 107
    :goto_1
    if-eqz p1, :cond_3

    .line 108
    .line 109
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p1, Lg40/o0;

    .line 112
    .line 113
    if-eqz p1, :cond_3

    .line 114
    .line 115
    iget-object p1, p1, Lg40/o0;->b:Ljava/lang/String;

    .line 116
    .line 117
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/j4;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    :cond_3
    move-object v11, v1

    .line 122
    const/16 v12, 0x7ff

    .line 123
    .line 124
    const/4 v1, 0x0

    .line 125
    const/4 v2, 0x0

    .line 126
    const/4 v3, 0x0

    .line 127
    const/4 v4, 0x0

    .line 128
    const/4 v5, 0x0

    .line 129
    const/4 v6, 0x0

    .line 130
    const/4 v7, 0x0

    .line 131
    const/4 v8, 0x0

    .line 132
    const/4 v9, 0x0

    .line 133
    const/4 v10, 0x0

    .line 134
    invoke-static/range {v0 .. v12}, Lh40/e1;->a(Lh40/e1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;Ljava/lang/String;I)Lh40/e1;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 139
    .line 140
    .line 141
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    return-object p0

    .line 144
    :pswitch_1
    check-cast p1, Lcq0/n;

    .line 145
    .line 146
    if-eqz p1, :cond_6

    .line 147
    .line 148
    iget-object p0, p0, Lh40/b1;->e:Lh40/f1;

    .line 149
    .line 150
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 151
    .line 152
    .line 153
    move-result-object p2

    .line 154
    move-object v0, p2

    .line 155
    check-cast v0, Lh40/e1;

    .line 156
    .line 157
    new-instance v9, Lh40/d1;

    .line 158
    .line 159
    iget-object p2, p1, Lcq0/n;->a:Ljava/lang/String;

    .line 160
    .line 161
    iget-object v1, p1, Lcq0/n;->c:Ljava/lang/String;

    .line 162
    .line 163
    iget-object v2, p1, Lcq0/n;->f:Lcq0/h;

    .line 164
    .line 165
    if-eqz v2, :cond_4

    .line 166
    .line 167
    const/4 v3, 0x0

    .line 168
    invoke-static {v2, v3}, Ljp/gg;->c(Lcq0/h;Z)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    if-nez v2, :cond_5

    .line 173
    .line 174
    :cond_4
    const-string v2, ""

    .line 175
    .line 176
    :cond_5
    iget-object p1, p1, Lcq0/n;->h:Ljava/lang/String;

    .line 177
    .line 178
    invoke-direct {v9, p2, v1, v2, p1}, Lh40/d1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    const/4 v11, 0x0

    .line 182
    const/16 v12, 0xafe

    .line 183
    .line 184
    const/4 v1, 0x0

    .line 185
    const/4 v2, 0x0

    .line 186
    const/4 v3, 0x0

    .line 187
    const/4 v4, 0x0

    .line 188
    const/4 v5, 0x0

    .line 189
    const/4 v6, 0x0

    .line 190
    const/4 v7, 0x0

    .line 191
    const/4 v8, 0x0

    .line 192
    const/4 v10, 0x0

    .line 193
    invoke-static/range {v0 .. v12}, Lh40/e1;->a(Lh40/e1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;Ljava/lang/String;I)Lh40/e1;

    .line 194
    .line 195
    .line 196
    move-result-object p1

    .line 197
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 198
    .line 199
    .line 200
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 201
    .line 202
    return-object p0

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
