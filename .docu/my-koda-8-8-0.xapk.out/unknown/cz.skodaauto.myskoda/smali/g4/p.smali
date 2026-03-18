.class public final synthetic Lg4/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroidx/lifecycle/c1;


# direct methods
.method public synthetic constructor <init>(Landroidx/lifecycle/c1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg4/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg4/p;->e:Landroidx/lifecycle/c1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lg4/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg4/p;->e:Landroidx/lifecycle/c1;

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    move-object v1, v0

    .line 26
    check-cast v1, Lg4/r;

    .line 27
    .line 28
    iget-object v1, v1, Lg4/r;->a:Lo4/c;

    .line 29
    .line 30
    iget-object v1, v1, Lo4/c;->l:Lh4/f;

    .line 31
    .line 32
    invoke-virtual {v1}, Lh4/f;->c()F

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    const/4 v3, 0x1

    .line 41
    if-gt v3, v2, :cond_2

    .line 42
    .line 43
    :goto_0
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    move-object v5, v4

    .line 48
    check-cast v5, Lg4/r;

    .line 49
    .line 50
    iget-object v5, v5, Lg4/r;->a:Lo4/c;

    .line 51
    .line 52
    iget-object v5, v5, Lo4/c;->l:Lh4/f;

    .line 53
    .line 54
    invoke-virtual {v5}, Lh4/f;->c()F

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    invoke-static {v1, v5}, Ljava/lang/Float;->compare(FF)I

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    if-gez v6, :cond_1

    .line 63
    .line 64
    move-object v0, v4

    .line 65
    move v1, v5

    .line 66
    :cond_1
    if-eq v3, v2, :cond_2

    .line 67
    .line 68
    add-int/lit8 v3, v3, 0x1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_2
    move-object p0, v0

    .line 72
    :goto_1
    check-cast p0, Lg4/r;

    .line 73
    .line 74
    if-eqz p0, :cond_3

    .line 75
    .line 76
    iget-object p0, p0, Lg4/r;->a:Lo4/c;

    .line 77
    .line 78
    iget-object p0, p0, Lo4/c;->l:Lh4/f;

    .line 79
    .line 80
    invoke-virtual {p0}, Lh4/f;->c()F

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    goto :goto_2

    .line 85
    :cond_3
    const/4 p0, 0x0

    .line 86
    :goto_2
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_0
    iget-object p0, p0, Lg4/p;->e:Landroidx/lifecycle/c1;

    .line 92
    .line 93
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Ljava/util/ArrayList;

    .line 96
    .line 97
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    if-eqz v0, :cond_4

    .line 102
    .line 103
    const/4 p0, 0x0

    .line 104
    goto :goto_4

    .line 105
    :cond_4
    const/4 v0, 0x0

    .line 106
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    move-object v1, v0

    .line 111
    check-cast v1, Lg4/r;

    .line 112
    .line 113
    iget-object v1, v1, Lg4/r;->a:Lo4/c;

    .line 114
    .line 115
    invoke-virtual {v1}, Lo4/c;->c()F

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    const/4 v3, 0x1

    .line 124
    if-gt v3, v2, :cond_6

    .line 125
    .line 126
    :goto_3
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    move-object v5, v4

    .line 131
    check-cast v5, Lg4/r;

    .line 132
    .line 133
    iget-object v5, v5, Lg4/r;->a:Lo4/c;

    .line 134
    .line 135
    invoke-virtual {v5}, Lo4/c;->c()F

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    invoke-static {v1, v5}, Ljava/lang/Float;->compare(FF)I

    .line 140
    .line 141
    .line 142
    move-result v6

    .line 143
    if-gez v6, :cond_5

    .line 144
    .line 145
    move-object v0, v4

    .line 146
    move v1, v5

    .line 147
    :cond_5
    if-eq v3, v2, :cond_6

    .line 148
    .line 149
    add-int/lit8 v3, v3, 0x1

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_6
    move-object p0, v0

    .line 153
    :goto_4
    check-cast p0, Lg4/r;

    .line 154
    .line 155
    if-eqz p0, :cond_7

    .line 156
    .line 157
    iget-object p0, p0, Lg4/r;->a:Lo4/c;

    .line 158
    .line 159
    invoke-virtual {p0}, Lo4/c;->c()F

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    goto :goto_5

    .line 164
    :cond_7
    const/4 p0, 0x0

    .line 165
    :goto_5
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    return-object p0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
