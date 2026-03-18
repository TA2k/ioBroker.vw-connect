.class public final Lym/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lym/g;


# direct methods
.method public synthetic constructor <init>(Lym/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lym/e;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lym/e;->g:Lym/g;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lym/e;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lym/e;->g:Lym/g;

    .line 7
    .line 8
    invoke-virtual {p0}, Lym/g;->d()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iget-object v1, p0, Lym/g;->f:Ll2/j1;

    .line 13
    .line 14
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-ne v0, v1, :cond_0

    .line 25
    .line 26
    iget-object v0, p0, Lym/g;->n:Ll2/j1;

    .line 27
    .line 28
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, Ljava/lang/Number;

    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-virtual {p0}, Lym/g;->c()F

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    cmpg-float p0, v0, p0

    .line 43
    .line 44
    if-nez p0, :cond_0

    .line 45
    .line 46
    const/4 p0, 0x1

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 p0, 0x0

    .line 49
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :pswitch_0
    iget-object p0, p0, Lym/e;->g:Lym/g;

    .line 55
    .line 56
    iget-object v0, p0, Lym/g;->i:Ll2/j1;

    .line 57
    .line 58
    iget-object v1, p0, Lym/g;->g:Ll2/j1;

    .line 59
    .line 60
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Ljava/lang/Boolean;

    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_1

    .line 71
    .line 72
    invoke-virtual {p0}, Lym/g;->d()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    rem-int/lit8 p0, p0, 0x2

    .line 77
    .line 78
    if-nez p0, :cond_1

    .line 79
    .line 80
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    check-cast p0, Ljava/lang/Number;

    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    neg-float p0, p0

    .line 91
    goto :goto_1

    .line 92
    :cond_1
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    check-cast p0, Ljava/lang/Number;

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    :goto_1
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :pswitch_1
    iget-object p0, p0, Lym/e;->g:Lym/g;

    .line 108
    .line 109
    iget-object v0, p0, Lym/g;->h:Ll2/j1;

    .line 110
    .line 111
    iget-object v1, p0, Lym/g;->l:Ll2/j1;

    .line 112
    .line 113
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Lum/a;

    .line 118
    .line 119
    const/4 v2, 0x0

    .line 120
    if-nez v1, :cond_2

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_2
    iget-object p0, p0, Lym/g;->i:Ll2/j1;

    .line 124
    .line 125
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    check-cast p0, Ljava/lang/Number;

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    cmpg-float p0, p0, v2

    .line 136
    .line 137
    if-gez p0, :cond_4

    .line 138
    .line 139
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-nez p0, :cond_3

    .line 144
    .line 145
    goto :goto_2

    .line 146
    :cond_3
    new-instance p0, Ljava/lang/ClassCastException;

    .line 147
    .line 148
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_4
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    if-nez p0, :cond_5

    .line 157
    .line 158
    const/high16 v2, 0x3f800000    # 1.0f

    .line 159
    .line 160
    :goto_2
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    return-object p0

    .line 165
    :cond_5
    new-instance p0, Ljava/lang/ClassCastException;

    .line 166
    .line 167
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 168
    .line 169
    .line 170
    throw p0

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
