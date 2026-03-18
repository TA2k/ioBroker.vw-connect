.class public final synthetic Lf30/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(ILx2/s;Z)V
    .locals 0

    .line 1
    const/4 p1, 0x4

    iput p1, p0, Lf30/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p3, p0, Lf30/c;->f:Z

    iput-object p2, p0, Lf30/c;->e:Lx2/s;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Z)V
    .locals 1

    .line 2
    const/4 v0, 0x3

    iput v0, p0, Lf30/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf30/c;->e:Lx2/s;

    iput-boolean p2, p0, Lf30/c;->f:Z

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZII)V
    .locals 0

    .line 3
    iput p4, p0, Lf30/c;->d:I

    iput-object p1, p0, Lf30/c;->e:Lx2/s;

    iput-boolean p2, p0, Lf30/c;->f:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lf30/c;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Lf30/c;->e:Lx2/s;

    .line 19
    .line 20
    iget-boolean p0, p0, Lf30/c;->f:Z

    .line 21
    .line 22
    invoke-static {p2, p1, v0, p0}, Lz10/a;->q(ILl2/o;Lx2/s;Z)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    and-int/lit8 v0, p2, 0x3

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    const/4 v2, 0x1

    .line 36
    if-eq v0, v1, :cond_0

    .line 37
    .line 38
    move v0, v2

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    const/4 v0, 0x0

    .line 41
    :goto_1
    and-int/2addr p2, v2

    .line 42
    move-object v6, p1

    .line 43
    check-cast v6, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-eqz p1, :cond_3

    .line 50
    .line 51
    new-instance v2, Lwk0/t;

    .line 52
    .line 53
    new-instance p1, Lwk0/u2;

    .line 54
    .line 55
    const-string p2, "www.example.com"

    .line 56
    .line 57
    const-string v0, "https://www.example.com"

    .line 58
    .line 59
    invoke-direct {p1, p2, v0}, Lwk0/u2;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    const-string p2, "+420 123 456 789"

    .line 63
    .line 64
    invoke-direct {v2, p2, p1}, Lwk0/t;-><init>(Ljava/lang/String;Lwk0/u2;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 72
    .line 73
    if-ne p1, p2, :cond_1

    .line 74
    .line 75
    new-instance p1, Lw81/d;

    .line 76
    .line 77
    const/16 v0, 0x1a

    .line 78
    .line 79
    invoke-direct {p1, v0}, Lw81/d;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v6, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_1
    move-object v4, p1

    .line 86
    check-cast v4, Lay0/k;

    .line 87
    .line 88
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    if-ne p1, p2, :cond_2

    .line 93
    .line 94
    new-instance p1, Lw81/d;

    .line 95
    .line 96
    const/16 p2, 0x19

    .line 97
    .line 98
    invoke-direct {p1, p2}, Lw81/d;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v6, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    :cond_2
    move-object v5, p1

    .line 105
    check-cast v5, Lay0/k;

    .line 106
    .line 107
    const/16 v7, 0x6c00

    .line 108
    .line 109
    iget-object v1, p0, Lf30/c;->e:Lx2/s;

    .line 110
    .line 111
    iget-boolean v3, p0, Lf30/c;->f:Z

    .line 112
    .line 113
    invoke-static/range {v1 .. v7}, Lxk0/h;->t(Lx2/s;Lwk0/t;ZLay0/k;Lay0/k;Ll2/o;I)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_3
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 118
    .line 119
    .line 120
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    const/4 p2, 0x7

    .line 127
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    iget-object v0, p0, Lf30/c;->e:Lx2/s;

    .line 132
    .line 133
    iget-boolean p0, p0, Lf30/c;->f:Z

    .line 134
    .line 135
    invoke-static {p2, p1, v0, p0}, Ls80/a;->f(ILl2/o;Lx2/s;Z)V

    .line 136
    .line 137
    .line 138
    goto :goto_0

    .line 139
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    const/4 p2, 0x7

    .line 143
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    iget-object v0, p0, Lf30/c;->e:Lx2/s;

    .line 148
    .line 149
    iget-boolean p0, p0, Lf30/c;->f:Z

    .line 150
    .line 151
    invoke-static {p2, p1, v0, p0}, Ls80/a;->f(ILl2/o;Lx2/s;Z)V

    .line 152
    .line 153
    .line 154
    goto/16 :goto_0

    .line 155
    .line 156
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    const/4 p2, 0x1

    .line 160
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 161
    .line 162
    .line 163
    move-result p2

    .line 164
    iget-object v0, p0, Lf30/c;->e:Lx2/s;

    .line 165
    .line 166
    iget-boolean p0, p0, Lf30/c;->f:Z

    .line 167
    .line 168
    invoke-static {p2, p1, v0, p0}, Lf30/a;->g(ILl2/o;Lx2/s;Z)V

    .line 169
    .line 170
    .line 171
    goto/16 :goto_0

    .line 172
    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
