.class public final Ln9/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:I

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I


# direct methods
.method public synthetic constructor <init>(IIIIII)V
    .locals 0

    .line 1
    iput p1, p0, Ln9/b;->a:I

    .line 2
    .line 3
    iput p2, p0, Ln9/b;->b:I

    .line 4
    .line 5
    iput p3, p0, Ln9/b;->c:I

    .line 6
    .line 7
    iput p4, p0, Ln9/b;->d:I

    .line 8
    .line 9
    iput p5, p0, Ln9/b;->e:I

    .line 10
    .line 11
    iput p6, p0, Ln9/b;->f:I

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public static a(Ljava/lang/String;)Ln9/b;
    .locals 10

    .line 1
    const-string v0, "Format:"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x7

    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, ","

    .line 16
    .line 17
    invoke-static {p0, v0}, Landroid/text/TextUtils;->split(Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/4 v0, -0x1

    .line 22
    const/4 v1, 0x0

    .line 23
    move v4, v0

    .line 24
    move v5, v4

    .line 25
    move v6, v5

    .line 26
    move v7, v6

    .line 27
    move v8, v7

    .line 28
    move v2, v1

    .line 29
    :goto_0
    array-length v3, p0

    .line 30
    if-ge v2, v3, :cond_5

    .line 31
    .line 32
    aget-object v3, p0, v2

    .line 33
    .line 34
    invoke-virtual {v3}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-static {v3}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    sparse-switch v9, :sswitch_data_0

    .line 50
    .line 51
    .line 52
    :goto_1
    move v3, v0

    .line 53
    goto :goto_2

    .line 54
    :sswitch_0
    const-string v9, "style"

    .line 55
    .line 56
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-nez v3, :cond_0

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_0
    const/4 v3, 0x4

    .line 64
    goto :goto_2

    .line 65
    :sswitch_1
    const-string v9, "start"

    .line 66
    .line 67
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-nez v3, :cond_1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    const/4 v3, 0x3

    .line 75
    goto :goto_2

    .line 76
    :sswitch_2
    const-string v9, "layer"

    .line 77
    .line 78
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    if-nez v3, :cond_2

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_2
    const/4 v3, 0x2

    .line 86
    goto :goto_2

    .line 87
    :sswitch_3
    const-string v9, "text"

    .line 88
    .line 89
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    if-nez v3, :cond_3

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_3
    const/4 v3, 0x1

    .line 97
    goto :goto_2

    .line 98
    :sswitch_4
    const-string v9, "end"

    .line 99
    .line 100
    invoke-virtual {v3, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    if-nez v3, :cond_4

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    move v3, v1

    .line 108
    :goto_2
    packed-switch v3, :pswitch_data_0

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :pswitch_0
    move v7, v2

    .line 113
    goto :goto_3

    .line 114
    :pswitch_1
    move v5, v2

    .line 115
    goto :goto_3

    .line 116
    :pswitch_2
    move v4, v2

    .line 117
    goto :goto_3

    .line 118
    :pswitch_3
    move v8, v2

    .line 119
    goto :goto_3

    .line 120
    :pswitch_4
    move v6, v2

    .line 121
    :goto_3
    add-int/lit8 v2, v2, 0x1

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_5
    if-eq v5, v0, :cond_6

    .line 125
    .line 126
    if-eq v6, v0, :cond_6

    .line 127
    .line 128
    if-eq v8, v0, :cond_6

    .line 129
    .line 130
    new-instance v3, Ln9/b;

    .line 131
    .line 132
    array-length v9, p0

    .line 133
    invoke-direct/range {v3 .. v9}, Ln9/b;-><init>(IIIIII)V

    .line 134
    .line 135
    .line 136
    return-object v3

    .line 137
    :cond_6
    const/4 p0, 0x0

    .line 138
    return-object p0

    .line 139
    :sswitch_data_0
    .sparse-switch
        0x188db -> :sswitch_4
        0x36452d -> :sswitch_3
        0x61fd551 -> :sswitch_2
        0x68ac462 -> :sswitch_1
        0x68b1db1 -> :sswitch_0
    .end sparse-switch

    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
