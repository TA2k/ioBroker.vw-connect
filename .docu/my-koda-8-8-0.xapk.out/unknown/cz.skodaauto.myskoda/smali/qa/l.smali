.class public final Lqa/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# static fields
.field public static final synthetic e:Lqa/l;


# instance fields
.field public final synthetic d:I


# direct methods
.method public static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lqa/l;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lqa/l;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lqa/l;->e:Lqa/l;

    .line 8
    .line 9
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lqa/l;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 2

    .line 1
    iget p0, p0, Lqa/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lxz/a;

    .line 7
    .line 8
    iget-object p0, p1, Lxz/a;->b:Ljava/lang/String;

    .line 9
    .line 10
    check-cast p2, Lxz/a;

    .line 11
    .line 12
    iget-object p1, p2, Lxz/a;->b:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :pswitch_0
    check-cast p1, Li31/e;

    .line 20
    .line 21
    iget p0, p1, Li31/e;->i:I

    .line 22
    .line 23
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p2, Li31/e;

    .line 28
    .line 29
    iget p1, p2, Li31/e;->i:I

    .line 30
    .line 31
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    return p0

    .line 40
    :pswitch_1
    check-cast p1, Li31/e;

    .line 41
    .line 42
    iget p0, p1, Li31/e;->i:I

    .line 43
    .line 44
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p2, Li31/e;

    .line 49
    .line 50
    iget p1, p2, Li31/e;->i:I

    .line 51
    .line 52
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    return p0

    .line 61
    :pswitch_2
    check-cast p1, Ler0/c;

    .line 62
    .line 63
    iget-object p0, p1, Ler0/c;->d:Ler0/b;

    .line 64
    .line 65
    check-cast p2, Ler0/c;

    .line 66
    .line 67
    iget-object p1, p2, Ler0/c;->d:Ler0/b;

    .line 68
    .line 69
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    return p0

    .line 74
    :pswitch_3
    check-cast p2, Lon0/a0;

    .line 75
    .line 76
    iget-boolean p0, p2, Lon0/a0;->a:Z

    .line 77
    .line 78
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p1, Lon0/a0;

    .line 83
    .line 84
    iget-boolean p1, p1, Lon0/a0;->a:Z

    .line 85
    .line 86
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    return p0

    .line 95
    :pswitch_4
    check-cast p2, Ljava/lang/Long;

    .line 96
    .line 97
    check-cast p1, Ljava/lang/Long;

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 100
    .line 101
    .line 102
    move-result-wide p0

    .line 103
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 104
    .line 105
    .line 106
    move-result-wide v0

    .line 107
    invoke-static {p0, p1, v0, v1}, Ljava/lang/Long;->compare(JJ)I

    .line 108
    .line 109
    .line 110
    move-result p0

    .line 111
    return p0

    .line 112
    :pswitch_5
    check-cast p1, Lv01/i;

    .line 113
    .line 114
    iget-object p0, p1, Lv01/i;->a:Lu01/y;

    .line 115
    .line 116
    check-cast p2, Lv01/i;

    .line 117
    .line 118
    iget-object p1, p2, Lv01/i;->a:Lu01/y;

    .line 119
    .line 120
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 121
    .line 122
    .line 123
    move-result p0

    .line 124
    return p0

    .line 125
    :pswitch_6
    check-cast p1, Lcz/myskoda/api/bff/v1/CardDto;

    .line 126
    .line 127
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/CardDto;->isDefault()Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    check-cast p2, Lcz/myskoda/api/bff/v1/CardDto;

    .line 136
    .line 137
    invoke-virtual {p2}, Lcz/myskoda/api/bff/v1/CardDto;->isDefault()Z

    .line 138
    .line 139
    .line 140
    move-result p1

    .line 141
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    return p0

    .line 150
    :pswitch_7
    check-cast p1, Lcz/myskoda/api/bff/v1/CardDto;

    .line 151
    .line 152
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/CardDto;->isDefault()Z

    .line 153
    .line 154
    .line 155
    move-result p0

    .line 156
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    check-cast p2, Lcz/myskoda/api/bff/v1/CardDto;

    .line 161
    .line 162
    invoke-virtual {p2}, Lcz/myskoda/api/bff/v1/CardDto;->isDefault()Z

    .line 163
    .line 164
    .line 165
    move-result p1

    .line 166
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    return p0

    .line 175
    :pswitch_8
    check-cast p1, Landroid/view/View;

    .line 176
    .line 177
    check-cast p2, Landroid/view/View;

    .line 178
    .line 179
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 180
    .line 181
    .line 182
    move-result p0

    .line 183
    invoke-virtual {p2}, Landroid/view/View;->getTop()I

    .line 184
    .line 185
    .line 186
    move-result p1

    .line 187
    sub-int/2addr p0, p1

    .line 188
    return p0

    .line 189
    :pswitch_9
    check-cast p1, Lqa/j;

    .line 190
    .line 191
    iget-object p0, p1, Lqa/j;->a:Ljava/lang/String;

    .line 192
    .line 193
    check-cast p2, Lqa/j;

    .line 194
    .line 195
    iget-object p1, p2, Lqa/j;->a:Ljava/lang/String;

    .line 196
    .line 197
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 198
    .line 199
    .line 200
    move-result p0

    .line 201
    return p0

    .line 202
    :pswitch_a
    check-cast p1, Lqa/h;

    .line 203
    .line 204
    iget-object p0, p1, Lqa/h;->a:Ljava/lang/String;

    .line 205
    .line 206
    check-cast p2, Lqa/h;

    .line 207
    .line 208
    iget-object p1, p2, Lqa/h;->a:Ljava/lang/String;

    .line 209
    .line 210
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 211
    .line 212
    .line 213
    move-result p0

    .line 214
    return p0

    .line 215
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
