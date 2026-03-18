.class public final synthetic Lb71/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Ll2/b1;)V
    .locals 0

    .line 1
    iput p1, p0, Lb71/h;->d:I

    iput-object p2, p0, Lb71/h;->e:Lay0/a;

    iput-object p3, p0, Lb71/h;->f:Ll2/b1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Ll2/b1;)V
    .locals 1

    .line 2
    const/16 v0, 0xa

    iput v0, p0, Lb71/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lb71/h;->f:Ll2/b1;

    iput-object p1, p0, Lb71/h;->e:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lb71/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 7
    .line 8
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 14
    .line 15
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_0
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 22
    .line 23
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 29
    .line 30
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :pswitch_1
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 35
    .line 36
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 42
    .line 43
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_2
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 48
    .line 49
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 50
    .line 51
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 55
    .line 56
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :pswitch_3
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 61
    .line 62
    iget-object v1, p0, Lb71/h;->f:Ll2/b1;

    .line 63
    .line 64
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 68
    .line 69
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :pswitch_4
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 74
    .line 75
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 81
    .line 82
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :pswitch_5
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 87
    .line 88
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 89
    .line 90
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 94
    .line 95
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :pswitch_6
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 100
    .line 101
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 102
    .line 103
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 107
    .line 108
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :pswitch_7
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 113
    .line 114
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 120
    .line 121
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    goto :goto_0

    .line 125
    :pswitch_8
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 126
    .line 127
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 128
    .line 129
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 133
    .line 134
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :pswitch_9
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 139
    .line 140
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 141
    .line 142
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 146
    .line 147
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    goto/16 :goto_0

    .line 151
    .line 152
    :pswitch_a
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 153
    .line 154
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 155
    .line 156
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 160
    .line 161
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    goto/16 :goto_0

    .line 165
    .line 166
    :pswitch_b
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 167
    .line 168
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 169
    .line 170
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 174
    .line 175
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    goto/16 :goto_0

    .line 179
    .line 180
    :pswitch_c
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 181
    .line 182
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 183
    .line 184
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 188
    .line 189
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    goto/16 :goto_0

    .line 193
    .line 194
    :pswitch_d
    iget-object v0, p0, Lb71/h;->f:Ll2/b1;

    .line 195
    .line 196
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 197
    .line 198
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    iget-object p0, p0, Lb71/h;->e:Lay0/a;

    .line 202
    .line 203
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    goto/16 :goto_0

    .line 207
    .line 208
    nop

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_d
        :pswitch_c
        :pswitch_b
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
