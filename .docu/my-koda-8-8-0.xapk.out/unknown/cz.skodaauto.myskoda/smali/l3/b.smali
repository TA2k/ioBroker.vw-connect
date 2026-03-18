.class public final Ll3/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll3/a;


# instance fields
.field public final synthetic a:I

.field public final b:Landroid/view/View;


# direct methods
.method public synthetic constructor <init>(Landroid/view/View;I)V
    .locals 0

    .line 1
    iput p2, p0, Ll3/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Ll3/b;->b:Landroid/view/View;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(I)V
    .locals 1

    .line 1
    iget v0, p0, Ll3/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ll3/b;->b:Landroid/view/View;

    .line 7
    .line 8
    const/16 v0, 0x10

    .line 9
    .line 10
    if-ne p1, v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 13
    .line 14
    .line 15
    goto/16 :goto_0

    .line 16
    .line 17
    :cond_0
    const/4 v0, 0x6

    .line 18
    if-ne p1, v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    const/16 v0, 0xd

    .line 25
    .line 26
    if-ne p1, v0, :cond_2

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    const/16 v0, 0x17

    .line 33
    .line 34
    if-ne p1, v0, :cond_3

    .line 35
    .line 36
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_3
    const/4 v0, 0x3

    .line 41
    if-ne p1, v0, :cond_4

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_4
    if-nez p1, :cond_5

    .line 48
    .line 49
    const/4 p1, 0x0

    .line 50
    invoke-virtual {p0, p1}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_5
    const/16 v0, 0x11

    .line 55
    .line 56
    if-ne p1, v0, :cond_6

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_6
    const/16 v0, 0x1b

    .line 63
    .line 64
    if-ne p1, v0, :cond_7

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_7
    const/16 v0, 0x1a

    .line 71
    .line 72
    if-ne p1, v0, :cond_8

    .line 73
    .line 74
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_8
    const/16 v0, 0x9

    .line 79
    .line 80
    if-ne p1, v0, :cond_9

    .line 81
    .line 82
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_9
    const/16 v0, 0x16

    .line 87
    .line 88
    if-ne p1, v0, :cond_a

    .line 89
    .line 90
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_a
    const/16 v0, 0x15

    .line 95
    .line 96
    if-ne p1, v0, :cond_b

    .line 97
    .line 98
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_b
    const/4 v0, 0x1

    .line 103
    if-ne p1, v0, :cond_c

    .line 104
    .line 105
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 106
    .line 107
    .line 108
    :cond_c
    :goto_0
    return-void

    .line 109
    :pswitch_0
    iget-object p0, p0, Ll3/b;->b:Landroid/view/View;

    .line 110
    .line 111
    check-cast p0, Lw3/t;

    .line 112
    .line 113
    const/16 v0, 0x10

    .line 114
    .line 115
    if-ne p1, v0, :cond_d

    .line 116
    .line 117
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 118
    .line 119
    .line 120
    goto/16 :goto_1

    .line 121
    .line 122
    :cond_d
    const/4 v0, 0x6

    .line 123
    if-ne p1, v0, :cond_e

    .line 124
    .line 125
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_e
    const/16 v0, 0xd

    .line 130
    .line 131
    if-ne p1, v0, :cond_f

    .line 132
    .line 133
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_f
    const/16 v0, 0x17

    .line 138
    .line 139
    if-ne p1, v0, :cond_10

    .line 140
    .line 141
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 142
    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_10
    const/4 v0, 0x3

    .line 146
    if-ne p1, v0, :cond_11

    .line 147
    .line 148
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 149
    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_11
    if-nez p1, :cond_12

    .line 153
    .line 154
    const/4 p1, 0x0

    .line 155
    invoke-virtual {p0, p1}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_12
    const/16 v0, 0x11

    .line 160
    .line 161
    if-ne p1, v0, :cond_13

    .line 162
    .line 163
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 164
    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_13
    const/16 v0, 0x1b

    .line 168
    .line 169
    if-ne p1, v0, :cond_14

    .line 170
    .line 171
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 172
    .line 173
    .line 174
    goto :goto_1

    .line 175
    :cond_14
    const/16 v0, 0x1a

    .line 176
    .line 177
    if-ne p1, v0, :cond_15

    .line 178
    .line 179
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 180
    .line 181
    .line 182
    goto :goto_1

    .line 183
    :cond_15
    const/16 v0, 0x9

    .line 184
    .line 185
    if-ne p1, v0, :cond_16

    .line 186
    .line 187
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 188
    .line 189
    .line 190
    goto :goto_1

    .line 191
    :cond_16
    const/16 v0, 0x16

    .line 192
    .line 193
    if-ne p1, v0, :cond_17

    .line 194
    .line 195
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 196
    .line 197
    .line 198
    goto :goto_1

    .line 199
    :cond_17
    const/16 v0, 0x15

    .line 200
    .line 201
    if-ne p1, v0, :cond_18

    .line 202
    .line 203
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 204
    .line 205
    .line 206
    goto :goto_1

    .line 207
    :cond_18
    const/4 v0, 0x1

    .line 208
    if-ne p1, v0, :cond_19

    .line 209
    .line 210
    invoke-virtual {p0, v0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 211
    .line 212
    .line 213
    :cond_19
    :goto_1
    return-void

    .line 214
    nop

    .line 215
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
