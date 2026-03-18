.class public final synthetic Lc81/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lc81/d;

.field public final synthetic e:S

.field public final synthetic f:Z

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:F

.field public final synthetic j:F


# direct methods
.method public synthetic constructor <init>(Lc81/d;SZFFFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc81/b;->d:Lc81/d;

    .line 5
    .line 6
    iput-short p2, p0, Lc81/b;->e:S

    .line 7
    .line 8
    iput-boolean p3, p0, Lc81/b;->f:Z

    .line 9
    .line 10
    iput p4, p0, Lc81/b;->g:F

    .line 11
    .line 12
    iput p5, p0, Lc81/b;->h:F

    .line 13
    .line 14
    iput p6, p0, Lc81/b;->i:F

    .line 15
    .line 16
    iput p7, p0, Lc81/b;->j:F

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Lc81/b;->d:Lc81/d;

    .line 2
    .line 3
    iget-object v1, v0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 4
    .line 5
    iget-object v2, v0, Lc81/d;->e:Lt71/a;

    .line 6
    .line 7
    if-eqz v2, :cond_c

    .line 8
    .line 9
    iget-short v3, p0, Lc81/b;->e:S

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    const/4 v5, 0x1

    .line 13
    if-le v3, v5, :cond_0

    .line 14
    .line 15
    move v3, v5

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v3, v4

    .line 18
    :goto_0
    iget-object v6, v0, Lc81/d;->a:Ll71/w;

    .line 19
    .line 20
    if-eqz v3, :cond_3

    .line 21
    .line 22
    iget-boolean v7, v0, Lc81/d;->h:Z

    .line 23
    .line 24
    if-nez v7, :cond_1

    .line 25
    .line 26
    iput-boolean v5, v0, Lc81/d;->h:Z

    .line 27
    .line 28
    iget-object v5, v6, Ll71/w;->b:Lu61/b;

    .line 29
    .line 30
    const-string v7, "handleMultiTouchDetection(): MULTI_TOUCH_DETECTED!"

    .line 31
    .line 32
    invoke-static {v5, v7}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    :cond_1
    sget-object v5, Ls71/p;->E:Ls71/p;

    .line 36
    .line 37
    iput-object v5, v2, Lt71/a;->b:Ls71/q;

    .line 38
    .line 39
    iget-object v7, v2, Lt71/a;->g:Lt71/b;

    .line 40
    .line 41
    if-eqz v7, :cond_2

    .line 42
    .line 43
    invoke-interface {v7, v2}, Lt71/b;->userActionDidChange(Lt71/a;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    invoke-static {v2, v5}, Lt71/a;->a(Lt71/a;Ls71/p;)Lt71/a;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 51
    .line 52
    invoke-direct {v7, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;-><init>(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->reactToInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Z

    .line 56
    .line 57
    .line 58
    :cond_3
    iget-boolean v5, v0, Lc81/d;->h:Z

    .line 59
    .line 60
    iget-boolean v7, p0, Lc81/b;->f:Z

    .line 61
    .line 62
    if-eqz v5, :cond_5

    .line 63
    .line 64
    if-eqz v7, :cond_5

    .line 65
    .line 66
    iput-boolean v4, v0, Lc81/d;->h:Z

    .line 67
    .line 68
    iget-object v4, v6, Ll71/w;->b:Lu61/b;

    .line 69
    .line 70
    const-string v5, "handleMultiTouchDetection(): MULTI_TOUCH_ENDED."

    .line 71
    .line 72
    invoke-static {v4, v5}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    sget-object v4, Ls71/p;->F:Ls71/p;

    .line 76
    .line 77
    iput-object v4, v2, Lt71/a;->b:Ls71/q;

    .line 78
    .line 79
    iget-object v5, v2, Lt71/a;->g:Lt71/b;

    .line 80
    .line 81
    if-eqz v5, :cond_4

    .line 82
    .line 83
    invoke-interface {v5, v2}, Lt71/b;->userActionDidChange(Lt71/a;)V

    .line 84
    .line 85
    .line 86
    :cond_4
    invoke-static {v2, v4}, Lt71/a;->a(Lt71/a;Ls71/p;)Lt71/a;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 91
    .line 92
    invoke-direct {v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;-><init>(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->reactToInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Z

    .line 96
    .line 97
    .line 98
    :cond_5
    if-nez v7, :cond_a

    .line 99
    .line 100
    if-eqz v3, :cond_6

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_6
    iget-object v1, v0, Lc81/d;->g:Lin/t1;

    .line 104
    .line 105
    iget v3, p0, Lc81/b;->g:F

    .line 106
    .line 107
    iget v4, p0, Lc81/b;->h:F

    .line 108
    .line 109
    if-eqz v1, :cond_7

    .line 110
    .line 111
    iget v5, v1, Lin/t1;->a:F

    .line 112
    .line 113
    cmpg-float v5, v5, v3

    .line 114
    .line 115
    if-nez v5, :cond_7

    .line 116
    .line 117
    iget v5, v1, Lin/t1;->b:F

    .line 118
    .line 119
    cmpg-float v5, v5, v4

    .line 120
    .line 121
    if-nez v5, :cond_7

    .line 122
    .line 123
    iget-object v0, v1, Lin/t1;->c:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Ljava/util/ArrayList;

    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_7
    new-instance v1, Lin/t1;

    .line 129
    .line 130
    invoke-direct {v1, v3, v4}, Lin/t1;-><init>(FF)V

    .line 131
    .line 132
    .line 133
    iput-object v1, v0, Lc81/d;->g:Lin/t1;

    .line 134
    .line 135
    iget-object v0, v1, Lin/t1;->c:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v0, Ljava/util/ArrayList;

    .line 138
    .line 139
    :goto_1
    const-string v1, "<this>"

    .line 140
    .line 141
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    :cond_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-eqz v1, :cond_9

    .line 153
    .line 154
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    move-object v3, v1

    .line 159
    check-cast v3, Lu71/b;

    .line 160
    .line 161
    iget-object v4, v3, Lu71/b;->c:Lu71/a;

    .line 162
    .line 163
    iget v5, v4, Lu71/a;->a:F

    .line 164
    .line 165
    iget-object v3, v3, Lu71/b;->f:Lu71/a;

    .line 166
    .line 167
    iget v6, v3, Lu71/a;->a:F

    .line 168
    .line 169
    iget v7, p0, Lc81/b;->i:F

    .line 170
    .line 171
    cmpg-float v5, v5, v7

    .line 172
    .line 173
    if-gtz v5, :cond_8

    .line 174
    .line 175
    cmpg-float v5, v7, v6

    .line 176
    .line 177
    if-gtz v5, :cond_8

    .line 178
    .line 179
    iget v4, v4, Lu71/a;->b:F

    .line 180
    .line 181
    iget v3, v3, Lu71/a;->b:F

    .line 182
    .line 183
    iget v5, p0, Lc81/b;->j:F

    .line 184
    .line 185
    cmpg-float v4, v4, v5

    .line 186
    .line 187
    if-gtz v4, :cond_8

    .line 188
    .line 189
    cmpg-float v3, v5, v3

    .line 190
    .line 191
    if-gtz v3, :cond_8

    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_9
    const/4 v1, 0x0

    .line 195
    :goto_2
    check-cast v1, Lu71/b;

    .line 196
    .line 197
    if-nez v1, :cond_b

    .line 198
    .line 199
    sget-object v1, Lu71/b;->g:Lu71/b;

    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_a
    :goto_3
    sget-object v1, Lu71/b;->g:Lu71/b;

    .line 203
    .line 204
    :cond_b
    :goto_4
    const-string p0, "value"

    .line 205
    .line 206
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    iget-object p0, v2, Lt71/a;->d:Lu71/b;

    .line 210
    .line 211
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result p0

    .line 215
    if-nez p0, :cond_c

    .line 216
    .line 217
    iput-object v1, v2, Lt71/a;->d:Lu71/b;

    .line 218
    .line 219
    iget-object p0, v2, Lt71/a;->g:Lt71/b;

    .line 220
    .line 221
    if-eqz p0, :cond_c

    .line 222
    .line 223
    invoke-interface {p0, v2}, Lt71/b;->touchPositionDidChange(Lt71/a;)V

    .line 224
    .line 225
    .line 226
    :cond_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 227
    .line 228
    return-object p0
.end method
