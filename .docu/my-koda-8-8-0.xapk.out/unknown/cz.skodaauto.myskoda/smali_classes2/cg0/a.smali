.class public final Lcg0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyf0/a;


# direct methods
.method public constructor <init>(Lyf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcg0/a;->a:Lyf0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 14

    .line 1
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Lbg0/c;

    .line 10
    .line 11
    sget-object v2, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 12
    .line 13
    const-string v3, "Android "

    .line 14
    .line 15
    invoke-static {v3, v2}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 20
    .line 21
    sget-object v4, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 22
    .line 23
    const-string v5, "MANUFACTURER"

    .line 24
    .line 25
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    sget-object v4, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 29
    .line 30
    const-string v5, "MODEL"

    .line 31
    .line 32
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    const/4 v5, 0x0

    .line 40
    invoke-virtual {v4, v5}, Landroid/os/LocaleList;->get(I)Ljava/util/Locale;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {v4}, Ljava/util/Locale;->getDisplayLanguage()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    const-string v6, "getDisplayLanguage(...)"

    .line 49
    .line 50
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    invoke-virtual {v6, v5}, Landroid/os/LocaleList;->get(I)Ljava/util/Locale;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    invoke-virtual {v6}, Ljava/util/Locale;->getCountry()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    const-string v7, "getCountry(...)"

    .line 66
    .line 67
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    sget v7, Lh/n;->e:I

    .line 71
    .line 72
    const/4 v8, 0x2

    .line 73
    const/4 v9, 0x1

    .line 74
    if-eq v7, v9, :cond_1

    .line 75
    .line 76
    if-eq v7, v8, :cond_0

    .line 77
    .line 78
    iget v7, v0, Landroid/content/res/Configuration;->uiMode:I

    .line 79
    .line 80
    and-int/lit8 v7, v7, 0x30

    .line 81
    .line 82
    const/16 v10, 0x20

    .line 83
    .line 84
    if-ne v7, v10, :cond_1

    .line 85
    .line 86
    :cond_0
    move v5, v9

    .line 87
    :cond_1
    iget v7, v0, Landroid/content/res/Configuration;->screenLayout:I

    .line 88
    .line 89
    and-int/lit8 v7, v7, 0xf

    .line 90
    .line 91
    if-eq v7, v9, :cond_5

    .line 92
    .line 93
    if-eq v7, v8, :cond_4

    .line 94
    .line 95
    const/4 v8, 0x3

    .line 96
    if-eq v7, v8, :cond_3

    .line 97
    .line 98
    const/4 v8, 0x4

    .line 99
    if-eq v7, v8, :cond_2

    .line 100
    .line 101
    sget-object v7, Lbg0/b;->h:Lbg0/b;

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_2
    sget-object v7, Lbg0/b;->g:Lbg0/b;

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_3
    sget-object v7, Lbg0/b;->e:Lbg0/b;

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_4
    sget-object v7, Lbg0/b;->d:Lbg0/b;

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_5
    sget-object v7, Lbg0/b;->f:Lbg0/b;

    .line 114
    .line 115
    :goto_0
    iget v10, v0, Landroid/content/res/Configuration;->densityDpi:I

    .line 116
    .line 117
    const/16 v8, 0x78

    .line 118
    .line 119
    if-gt v10, v8, :cond_6

    .line 120
    .line 121
    sget-object v8, Lbg0/a;->d:Lbg0/a;

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_6
    const/16 v8, 0xa0

    .line 125
    .line 126
    if-gt v10, v8, :cond_7

    .line 127
    .line 128
    sget-object v8, Lbg0/a;->e:Lbg0/a;

    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_7
    const/16 v8, 0xf0

    .line 132
    .line 133
    if-gt v10, v8, :cond_8

    .line 134
    .line 135
    sget-object v8, Lbg0/a;->f:Lbg0/a;

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_8
    const/16 v8, 0x140

    .line 139
    .line 140
    if-gt v10, v8, :cond_9

    .line 141
    .line 142
    sget-object v8, Lbg0/a;->g:Lbg0/a;

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_9
    const/16 v8, 0x1e0

    .line 146
    .line 147
    if-gt v10, v8, :cond_a

    .line 148
    .line 149
    sget-object v8, Lbg0/a;->h:Lbg0/a;

    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_a
    sget-object v8, Lbg0/a;->i:Lbg0/a;

    .line 153
    .line 154
    :goto_1
    iget v9, v0, Landroid/content/res/Configuration;->fontScale:F

    .line 155
    .line 156
    iget v11, v0, Landroid/content/res/Configuration;->screenWidthDp:I

    .line 157
    .line 158
    iget v12, v0, Landroid/content/res/Configuration;->screenHeightDp:I

    .line 159
    .line 160
    move-object v13, v6

    .line 161
    move v6, v5

    .line 162
    move-object v5, v13

    .line 163
    invoke-direct/range {v1 .. v12}, Lbg0/c;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;ZLbg0/b;Lbg0/a;FIII)V

    .line 164
    .line 165
    .line 166
    iget-object p0, p0, Lcg0/a;->a:Lyf0/a;

    .line 167
    .line 168
    iget-object p0, p0, Lyf0/a;->a:Lyy0/c2;

    .line 169
    .line 170
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 171
    .line 172
    .line 173
    const/4 v0, 0x0

    .line 174
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    return-void
.end method
