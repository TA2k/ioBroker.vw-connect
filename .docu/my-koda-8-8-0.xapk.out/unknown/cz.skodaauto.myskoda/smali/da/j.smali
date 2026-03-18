.class public final Lda/j;
.super Lz9/g0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:Lda/j;


# instance fields
.field public final synthetic q:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lda/j;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Lda/j;-><init>(IZ)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lda/j;->r:Lda/j;

    .line 9
    .line 10
    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lda/j;->q:I

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lz9/g0;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lda/j;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "bundle"

    .line 7
    .line 8
    const-string v0, "key"

    .line 9
    .line 10
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    invoke-static {p1, p2}, Lkp/t;->g(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-string p0, "null"

    .line 28
    .line 29
    :goto_0
    return-object p0

    .line 30
    :pswitch_0
    const-string p0, "bundle"

    .line 31
    .line 32
    const-string v0, "key"

    .line 33
    .line 34
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-nez p0, :cond_1

    .line 45
    .line 46
    invoke-static {p1, p2}, Lkp/t;->d(Ljava/lang/String;Landroid/os/Bundle;)J

    .line 47
    .line 48
    .line 49
    move-result-wide p0

    .line 50
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    const/4 p0, 0x0

    .line 56
    :goto_1
    return-object p0

    .line 57
    :pswitch_1
    const-string p0, "bundle"

    .line 58
    .line 59
    const-string v0, "key"

    .line 60
    .line 61
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_2

    .line 66
    .line 67
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-nez p0, :cond_2

    .line 72
    .line 73
    invoke-static {p1, p2}, Lkp/t;->c(Ljava/lang/String;Landroid/os/Bundle;)I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    goto :goto_2

    .line 82
    :cond_2
    const/4 p0, 0x0

    .line 83
    :goto_2
    return-object p0

    .line 84
    :pswitch_2
    const-string p0, "bundle"

    .line 85
    .line 86
    const-string v0, "key"

    .line 87
    .line 88
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    if-eqz p0, :cond_3

    .line 93
    .line 94
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    if-nez p0, :cond_3

    .line 99
    .line 100
    invoke-static {p1, p2}, Lkp/t;->b(Ljava/lang/String;Landroid/os/Bundle;)F

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    goto :goto_3

    .line 109
    :cond_3
    const/4 p0, 0x0

    .line 110
    :goto_3
    return-object p0

    .line 111
    :pswitch_3
    const-string p0, "bundle"

    .line 112
    .line 113
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    const-string p0, "key"

    .line 117
    .line 118
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    invoke-static {p1, p2}, Lkp/t;->a(Ljava/lang/String;Landroid/os/Bundle;)D

    .line 122
    .line 123
    .line 124
    move-result-wide p0

    .line 125
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    :pswitch_4
    const-string p0, "bundle"

    .line 131
    .line 132
    const-string v0, "key"

    .line 133
    .line 134
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    if-eqz p0, :cond_4

    .line 139
    .line 140
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-nez p0, :cond_4

    .line 145
    .line 146
    invoke-static {p1, p2}, Lkp/t;->a(Ljava/lang/String;Landroid/os/Bundle;)D

    .line 147
    .line 148
    .line 149
    move-result-wide p0

    .line 150
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    goto :goto_4

    .line 155
    :cond_4
    const/4 p0, 0x0

    .line 156
    :goto_4
    return-object p0

    .line 157
    :pswitch_5
    const-string p0, "bundle"

    .line 158
    .line 159
    const-string v0, "key"

    .line 160
    .line 161
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    const/4 v0, 0x0

    .line 166
    if-eqz p0, :cond_7

    .line 167
    .line 168
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 169
    .line 170
    .line 171
    move-result p0

    .line 172
    if-nez p0, :cond_7

    .line 173
    .line 174
    const/4 p0, 0x0

    .line 175
    invoke-virtual {p2, p1, p0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 176
    .line 177
    .line 178
    move-result p0

    .line 179
    if-nez p0, :cond_6

    .line 180
    .line 181
    const/4 v1, 0x1

    .line 182
    invoke-virtual {p2, p1, v1}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 183
    .line 184
    .line 185
    move-result p2

    .line 186
    if-eq p2, v1, :cond_5

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_5
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw v0

    .line 193
    :cond_6
    :goto_5
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    :cond_7
    return-object v0

    .line 198
    :pswitch_6
    const-string p0, "bundle"

    .line 199
    .line 200
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    const-string p0, "key"

    .line 204
    .line 205
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    const/4 p0, 0x0

    .line 209
    return-object p0

    .line 210
    nop

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lda/j;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "string_non_nullable"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "long_nullable"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "integer_nullable"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    const-string p0, "float_nullable"

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    const-string p0, "double"

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    const-string p0, "double_nullable"

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    const-string p0, "boolean_nullable"

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    const-string p0, "unknown"

    .line 28
    .line 29
    return-object p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lda/j;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-object p1

    .line 7
    :pswitch_0
    const-string p0, "null"

    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    sget-object p0, Lz9/g0;->e:Lz9/e;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Ljava/lang/Long;

    .line 24
    .line 25
    :goto_0
    return-object p0

    .line 26
    :pswitch_1
    const-string p0, "null"

    .line 27
    .line 28
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    sget-object p0, Lz9/g0;->b:Lz9/e;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Ljava/lang/Integer;

    .line 43
    .line 44
    :goto_1
    return-object p0

    .line 45
    :pswitch_2
    const-string p0, "null"

    .line 46
    .line 47
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    if-eqz p0, :cond_2

    .line 52
    .line 53
    const/4 p0, 0x0

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    invoke-static {p1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    :goto_2
    return-object p0

    .line 64
    :pswitch_3
    invoke-static {p1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 65
    .line 66
    .line 67
    move-result-wide p0

    .line 68
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_4
    const-string p0, "null"

    .line 74
    .line 75
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-eqz p0, :cond_3

    .line 80
    .line 81
    const/4 p0, 0x0

    .line 82
    goto :goto_3

    .line 83
    :cond_3
    invoke-static {p1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 84
    .line 85
    .line 86
    move-result-wide p0

    .line 87
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    :goto_3
    return-object p0

    .line 92
    :pswitch_5
    const-string p0, "null"

    .line 93
    .line 94
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    if-eqz p0, :cond_4

    .line 99
    .line 100
    const/4 p0, 0x0

    .line 101
    goto :goto_4

    .line 102
    :cond_4
    sget-object p0, Lz9/g0;->k:Lz9/e;

    .line 103
    .line 104
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    check-cast p0, Ljava/lang/Boolean;

    .line 109
    .line 110
    :goto_4
    return-object p0

    .line 111
    :pswitch_6
    const-string p0, "null"

    .line 112
    .line 113
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget p0, p0, Lda/j;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p3, Ljava/lang/String;

    .line 7
    .line 8
    const-string p0, "key"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "value"

    .line 14
    .line 15
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {p2, p3, p1}, Lkp/v;->e(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    check-cast p3, Ljava/lang/Long;

    .line 23
    .line 24
    const-string p0, "key"

    .line 25
    .line 26
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    if-nez p3, :cond_0

    .line 30
    .line 31
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    sget-object p0, Lz9/g0;->e:Lz9/e;

    .line 36
    .line 37
    invoke-virtual {p0, p1, p2, p3}, Lz9/e;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    :goto_0
    return-void

    .line 41
    :pswitch_1
    check-cast p3, Ljava/lang/Integer;

    .line 42
    .line 43
    const-string p0, "key"

    .line 44
    .line 45
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    if-nez p3, :cond_1

    .line 49
    .line 50
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    sget-object p0, Lz9/g0;->b:Lz9/e;

    .line 55
    .line 56
    invoke-virtual {p0, p1, p2, p3}, Lz9/e;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :goto_1
    return-void

    .line 60
    :pswitch_2
    check-cast p3, Ljava/lang/Float;

    .line 61
    .line 62
    const-string p0, "key"

    .line 63
    .line 64
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    if-nez p3, :cond_2

    .line 68
    .line 69
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    sget-object p0, Lz9/g0;->h:Lz9/e;

    .line 74
    .line 75
    invoke-virtual {p0, p1, p2, p3}, Lz9/e;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :goto_2
    return-void

    .line 79
    :pswitch_3
    check-cast p3, Ljava/lang/Number;

    .line 80
    .line 81
    invoke-virtual {p3}, Ljava/lang/Number;->doubleValue()D

    .line 82
    .line 83
    .line 84
    move-result-wide v0

    .line 85
    const-string p0, "key"

    .line 86
    .line 87
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, p2, v0, v1}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :pswitch_4
    check-cast p3, Ljava/lang/Double;

    .line 95
    .line 96
    const-string p0, "key"

    .line 97
    .line 98
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    if-nez p3, :cond_3

    .line 102
    .line 103
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 104
    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_3
    invoke-virtual {p3}, Ljava/lang/Number;->doubleValue()D

    .line 108
    .line 109
    .line 110
    move-result-wide v0

    .line 111
    invoke-virtual {p1, p2, v0, v1}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 112
    .line 113
    .line 114
    :goto_3
    return-void

    .line 115
    :pswitch_5
    check-cast p3, Ljava/lang/Boolean;

    .line 116
    .line 117
    const-string p0, "key"

    .line 118
    .line 119
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    if-nez p3, :cond_4

    .line 123
    .line 124
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 125
    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_4
    sget-object p0, Lz9/g0;->k:Lz9/e;

    .line 129
    .line 130
    invoke-virtual {p0, p1, p2, p3}, Lz9/e;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :goto_4
    return-void

    .line 134
    :pswitch_6
    check-cast p3, Ljava/lang/String;

    .line 135
    .line 136
    const-string p0, "key"

    .line 137
    .line 138
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const-string p0, "value"

    .line 142
    .line 143
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    return-void

    .line 147
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public f(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lda/j;->q:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lz9/g0;->f(Ljava/lang/Object;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 12
    .line 13
    const-string p0, "value"

    .line 14
    .line 15
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1}, Lz9/h0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_0
    .end packed-switch
.end method
