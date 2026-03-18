.class public final synthetic Lmh/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmh/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmh/l;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lmh/l;->f:Ll2/b1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lmh/l;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    check-cast p3, Ll2/o;

    .line 8
    .line 9
    check-cast p4, Ljava/lang/Integer;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const-string p4, "$this$composable"

    .line 18
    .line 19
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string p1, "it"

    .line 23
    .line 24
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    new-instance p1, Ldi/a;

    .line 28
    .line 29
    iget-object p2, p0, Lmh/l;->f:Ll2/b1;

    .line 30
    .line 31
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    check-cast p2, Ljava/lang/String;

    .line 36
    .line 37
    const/4 p4, 0x1

    .line 38
    invoke-direct {p1, p2, p4, p4}, Ldi/a;-><init>(Ljava/lang/String;ZZ)V

    .line 39
    .line 40
    .line 41
    check-cast p3, Ll2/t;

    .line 42
    .line 43
    iget-object p0, p0, Lmh/l;->e:Lay0/k;

    .line 44
    .line 45
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p4

    .line 53
    if-nez p2, :cond_0

    .line 54
    .line 55
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 56
    .line 57
    if-ne p4, p2, :cond_1

    .line 58
    .line 59
    :cond_0
    new-instance p4, Llk/f;

    .line 60
    .line 61
    const/16 p2, 0x10

    .line 62
    .line 63
    invoke-direct {p4, p2, p0}, Llk/f;-><init>(ILay0/k;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p3, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    :cond_1
    check-cast p4, Lay0/a;

    .line 70
    .line 71
    const/4 p0, 0x0

    .line 72
    invoke-static {p1, p4, p3, p0}, Ljp/ub;->c(Ldi/a;Lay0/a;Ll2/o;I)V

    .line 73
    .line 74
    .line 75
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_0
    const-string v0, "$this$composable"

    .line 79
    .line 80
    const-string v1, "it"

    .line 81
    .line 82
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lmh/l;->f:Ll2/b1;

    .line 86
    .line 87
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    check-cast p1, Ljava/lang/String;

    .line 92
    .line 93
    check-cast p3, Ll2/t;

    .line 94
    .line 95
    iget-object p0, p0, Lmh/l;->e:Lay0/k;

    .line 96
    .line 97
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p2

    .line 101
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p4

    .line 105
    if-nez p2, :cond_2

    .line 106
    .line 107
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 108
    .line 109
    if-ne p4, p2, :cond_3

    .line 110
    .line 111
    :cond_2
    new-instance p4, Llk/f;

    .line 112
    .line 113
    const/16 p2, 0x15

    .line 114
    .line 115
    invoke-direct {p4, p2, p0}, Llk/f;-><init>(ILay0/k;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p3, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_3
    check-cast p4, Lay0/a;

    .line 122
    .line 123
    const/4 p0, 0x0

    .line 124
    invoke-static {p1, p4, p3, p0}, Ljp/od;->b(Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    :pswitch_1
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    const-string p4, "$this$composable"

    .line 132
    .line 133
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const-string p1, "it"

    .line 137
    .line 138
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    new-instance p1, Ldi/b;

    .line 142
    .line 143
    iget-object p2, p0, Lmh/l;->f:Ll2/b1;

    .line 144
    .line 145
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    check-cast p2, Ljava/lang/String;

    .line 150
    .line 151
    const-string p4, ""

    .line 152
    .line 153
    invoke-direct {p1, p2, p4}, Ldi/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    check-cast p3, Ll2/t;

    .line 157
    .line 158
    iget-object p0, p0, Lmh/l;->e:Lay0/k;

    .line 159
    .line 160
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result p2

    .line 164
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p4

    .line 168
    if-nez p2, :cond_4

    .line 169
    .line 170
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 171
    .line 172
    if-ne p4, p2, :cond_5

    .line 173
    .line 174
    :cond_4
    new-instance p4, Llk/f;

    .line 175
    .line 176
    const/16 p2, 0x14

    .line 177
    .line 178
    invoke-direct {p4, p2, p0}, Llk/f;-><init>(ILay0/k;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {p3, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    :cond_5
    check-cast p4, Lay0/a;

    .line 185
    .line 186
    const/4 p0, 0x0

    .line 187
    invoke-static {p1, p4, p3, p0}, Ljp/qf;->b(Ldi/b;Lay0/a;Ll2/o;I)V

    .line 188
    .line 189
    .line 190
    goto :goto_0

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
