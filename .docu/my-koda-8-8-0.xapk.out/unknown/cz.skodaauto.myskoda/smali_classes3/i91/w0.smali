.class public final synthetic Li91/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li91/c2;

.field public final synthetic f:Li91/t1;


# direct methods
.method public synthetic constructor <init>(Li91/c2;Li91/t1;I)V
    .locals 0

    .line 1
    iput p3, p0, Li91/w0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li91/w0;->e:Li91/c2;

    .line 4
    .line 5
    iput-object p2, p0, Li91/w0;->f:Li91/t1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li91/w0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Li91/k2;

    .line 8
    .line 9
    check-cast p2, Ll2/o;

    .line 10
    .line 11
    check-cast p3, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    const-string p3, "<this>"

    .line 18
    .line 19
    invoke-static {v1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    and-int/lit8 p3, p1, 0x6

    .line 23
    .line 24
    if-nez p3, :cond_1

    .line 25
    .line 26
    move-object p3, p2

    .line 27
    check-cast p3, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {p3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p3

    .line 33
    if-eqz p3, :cond_0

    .line 34
    .line 35
    const/4 p3, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p3, 0x2

    .line 38
    :goto_0
    or-int/2addr p1, p3

    .line 39
    :cond_1
    and-int/lit8 p3, p1, 0x13

    .line 40
    .line 41
    const/16 v0, 0x12

    .line 42
    .line 43
    if-eq p3, v0, :cond_2

    .line 44
    .line 45
    const/4 p3, 0x1

    .line 46
    goto :goto_1

    .line 47
    :cond_2
    const/4 p3, 0x0

    .line 48
    :goto_1
    and-int/lit8 v0, p1, 0x1

    .line 49
    .line 50
    move-object v7, p2

    .line 51
    check-cast v7, Ll2/t;

    .line 52
    .line 53
    invoke-virtual {v7, v0, p3}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eqz p2, :cond_4

    .line 58
    .line 59
    iget-object p2, p0, Li91/w0;->e:Li91/c2;

    .line 60
    .line 61
    iget-object v2, p2, Li91/c2;->d:Li91/v1;

    .line 62
    .line 63
    iget-boolean v3, p2, Li91/c2;->e:Z

    .line 64
    .line 65
    iget-object p0, p0, Li91/w0;->f:Li91/t1;

    .line 66
    .line 67
    if-eqz v3, :cond_3

    .line 68
    .line 69
    iget-wide v4, p0, Li91/t1;->e:J

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    iget-wide v4, p0, Li91/t1;->f:J

    .line 73
    .line 74
    :goto_2
    iget-object v6, p2, Li91/c2;->i:Ljava/lang/String;

    .line 75
    .line 76
    shl-int/lit8 p0, p1, 0xc

    .line 77
    .line 78
    const p1, 0xe000

    .line 79
    .line 80
    .line 81
    and-int v8, p0, p1

    .line 82
    .line 83
    invoke-virtual/range {v1 .. v8}, Li91/k2;->c(Li91/v1;ZJLjava/lang/String;Ll2/o;I)V

    .line 84
    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_4
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 88
    .line 89
    .line 90
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_0
    move-object v0, p1

    .line 94
    check-cast v0, Li91/t2;

    .line 95
    .line 96
    check-cast p2, Ll2/o;

    .line 97
    .line 98
    check-cast p3, Ljava/lang/Integer;

    .line 99
    .line 100
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    const-string p3, "<this>"

    .line 105
    .line 106
    invoke-static {v0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    and-int/lit8 p3, p1, 0x6

    .line 110
    .line 111
    if-nez p3, :cond_6

    .line 112
    .line 113
    move-object p3, p2

    .line 114
    check-cast p3, Ll2/t;

    .line 115
    .line 116
    invoke-virtual {p3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result p3

    .line 120
    if-eqz p3, :cond_5

    .line 121
    .line 122
    const/4 p3, 0x4

    .line 123
    goto :goto_4

    .line 124
    :cond_5
    const/4 p3, 0x2

    .line 125
    :goto_4
    or-int/2addr p1, p3

    .line 126
    :cond_6
    and-int/lit8 p3, p1, 0x13

    .line 127
    .line 128
    const/16 v1, 0x12

    .line 129
    .line 130
    if-eq p3, v1, :cond_7

    .line 131
    .line 132
    const/4 p3, 0x1

    .line 133
    goto :goto_5

    .line 134
    :cond_7
    const/4 p3, 0x0

    .line 135
    :goto_5
    and-int/lit8 v1, p1, 0x1

    .line 136
    .line 137
    move-object v6, p2

    .line 138
    check-cast v6, Ll2/t;

    .line 139
    .line 140
    invoke-virtual {v6, v1, p3}, Ll2/t;->O(IZ)Z

    .line 141
    .line 142
    .line 143
    move-result p2

    .line 144
    if-eqz p2, :cond_9

    .line 145
    .line 146
    iget-object p2, p0, Li91/w0;->e:Li91/c2;

    .line 147
    .line 148
    iget-object v1, p2, Li91/c2;->c:Li91/x1;

    .line 149
    .line 150
    iget-boolean v2, p2, Li91/c2;->e:Z

    .line 151
    .line 152
    iget-object p0, p0, Li91/w0;->f:Li91/t1;

    .line 153
    .line 154
    if-eqz v2, :cond_8

    .line 155
    .line 156
    iget-wide v3, p0, Li91/t1;->g:J

    .line 157
    .line 158
    goto :goto_6

    .line 159
    :cond_8
    iget-wide v3, p0, Li91/t1;->h:J

    .line 160
    .line 161
    :goto_6
    iget-object v5, p2, Li91/c2;->i:Ljava/lang/String;

    .line 162
    .line 163
    shl-int/lit8 p0, p1, 0xc

    .line 164
    .line 165
    const p1, 0xe000

    .line 166
    .line 167
    .line 168
    and-int v7, p0, p1

    .line 169
    .line 170
    invoke-virtual/range {v0 .. v7}, Li91/t2;->a(Li91/x1;ZJLjava/lang/String;Ll2/o;I)V

    .line 171
    .line 172
    .line 173
    goto :goto_7

    .line 174
    :cond_9
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 175
    .line 176
    .line 177
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    return-object p0

    .line 180
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
