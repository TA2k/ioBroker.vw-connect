.class public final Lco0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz4/f;

.field public final synthetic f:F


# direct methods
.method public synthetic constructor <init>(Lz4/f;FI)V
    .locals 0

    .line 1
    iput p3, p0, Lco0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lco0/f;->e:Lz4/f;

    .line 4
    .line 5
    iput p2, p0, Lco0/f;->f:F

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lco0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string v0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lco0/f;->e:Lz4/f;

    .line 14
    .line 15
    invoke-static {p1, v0}, Lz4/e;->b(Lz4/e;Lz4/f;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p1, Lz4/e;->d:Ly7/k;

    .line 19
    .line 20
    iget-object p1, p1, Lz4/e;->c:Lz4/f;

    .line 21
    .line 22
    iget-object p1, p1, Lz4/f;->d:Lz4/h;

    .line 23
    .line 24
    iget p0, p0, Lco0/f;->f:F

    .line 25
    .line 26
    const/4 v1, 0x4

    .line 27
    invoke-static {v0, p1, p0, v1}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 34
    .line 35
    const-string v0, "$this$constrainAs"

    .line 36
    .line 37
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    iget-object v0, p1, Lz4/e;->e:Ly41/a;

    .line 41
    .line 42
    iget-object v1, p0, Lco0/f;->e:Lz4/f;

    .line 43
    .line 44
    iget-object v1, v1, Lz4/f;->g:Lz4/g;

    .line 45
    .line 46
    iget p0, p0, Lco0/f;->f:F

    .line 47
    .line 48
    const/4 v2, 0x4

    .line 49
    invoke-static {v0, v1, p0, v2}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 50
    .line 51
    .line 52
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 53
    .line 54
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 55
    .line 56
    iget-object v1, v0, Lz4/f;->d:Lz4/h;

    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    const/4 v3, 0x6

    .line 60
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 61
    .line 62
    .line 63
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 64
    .line 65
    iget-object p1, v0, Lz4/f;->f:Lz4/h;

    .line 66
    .line 67
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 68
    .line 69
    .line 70
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object p0

    .line 73
    :pswitch_1
    check-cast p1, Lz4/e;

    .line 74
    .line 75
    const-string v0, "$this$constrainAs"

    .line 76
    .line 77
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget-object v0, p1, Lz4/e;->e:Ly41/a;

    .line 81
    .line 82
    iget-object v1, p0, Lco0/f;->e:Lz4/f;

    .line 83
    .line 84
    iget-object v1, v1, Lz4/f;->g:Lz4/g;

    .line 85
    .line 86
    iget p0, p0, Lco0/f;->f:F

    .line 87
    .line 88
    const/4 v2, 0x4

    .line 89
    invoke-static {v0, v1, p0, v2}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 93
    .line 94
    iget-object p1, p1, Lz4/e;->c:Lz4/f;

    .line 95
    .line 96
    iget-object p1, p1, Lz4/f;->d:Lz4/h;

    .line 97
    .line 98
    const/4 v0, 0x0

    .line 99
    const/4 v1, 0x6

    .line 100
    invoke-static {p0, p1, v0, v1}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 101
    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_2
    check-cast p1, Lz4/e;

    .line 107
    .line 108
    const-string v0, "$this$constrainAs"

    .line 109
    .line 110
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    iget-object v0, p1, Lz4/e;->e:Ly41/a;

    .line 114
    .line 115
    iget-object v1, p0, Lco0/f;->e:Lz4/f;

    .line 116
    .line 117
    iget-object v1, v1, Lz4/f;->g:Lz4/g;

    .line 118
    .line 119
    iget p0, p0, Lco0/f;->f:F

    .line 120
    .line 121
    const/4 v2, 0x4

    .line 122
    invoke-static {v0, v1, p0, v2}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 123
    .line 124
    .line 125
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 126
    .line 127
    iget-object p1, p1, Lz4/e;->c:Lz4/f;

    .line 128
    .line 129
    iget-object p1, p1, Lz4/f;->d:Lz4/h;

    .line 130
    .line 131
    const/4 v0, 0x0

    .line 132
    const/4 v1, 0x6

    .line 133
    invoke-static {p0, p1, v0, v1}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 134
    .line 135
    .line 136
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_3
    check-cast p1, Lz4/e;

    .line 140
    .line 141
    const-string v0, "$this$constrainAs"

    .line 142
    .line 143
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    iget-object v0, p1, Lz4/e;->e:Ly41/a;

    .line 147
    .line 148
    iget-object v1, p1, Lz4/e;->c:Lz4/f;

    .line 149
    .line 150
    iget-object v2, v1, Lz4/f;->e:Lz4/g;

    .line 151
    .line 152
    const/4 v3, 0x0

    .line 153
    const/4 v4, 0x6

    .line 154
    invoke-static {v0, v2, v3, v4}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 155
    .line 156
    .line 157
    iget-object v0, p1, Lz4/e;->d:Ly7/k;

    .line 158
    .line 159
    iget-object v1, v1, Lz4/f;->d:Lz4/h;

    .line 160
    .line 161
    invoke-static {v0, v1, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 162
    .line 163
    .line 164
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 165
    .line 166
    iget-object v1, p0, Lco0/f;->e:Lz4/f;

    .line 167
    .line 168
    iget-object v1, v1, Lz4/f;->d:Lz4/h;

    .line 169
    .line 170
    iget p0, p0, Lco0/f;->f:F

    .line 171
    .line 172
    const/4 v2, 0x4

    .line 173
    invoke-static {v0, v1, p0, v2}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 174
    .line 175
    .line 176
    new-instance p0, Lz4/n;

    .line 177
    .line 178
    const-string v0, "spread"

    .line 179
    .line 180
    invoke-direct {p0, v0}, Lz4/n;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {p1, p0}, Lz4/e;->c(Lz4/n;)V

    .line 184
    .line 185
    .line 186
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 187
    .line 188
    return-object p0

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
