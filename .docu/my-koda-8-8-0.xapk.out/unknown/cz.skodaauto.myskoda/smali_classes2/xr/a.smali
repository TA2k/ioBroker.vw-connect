.class public abstract Lxr/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhr/k0;

.field public static final b:Lhr/x0;

.field public static final c:Lhr/x0;

.field public static final d:Lhr/x0;

.field public static final e:Lhr/x0;

.field public static final f:Lhr/x0;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    const-string v7, "_exp_timeout"

    .line 2
    .line 3
    const-string v8, "_exp_expire"

    .line 4
    .line 5
    const-string v0, "_ac"

    .line 6
    .line 7
    const-string v1, "campaign_details"

    .line 8
    .line 9
    const-string v2, "_ug"

    .line 10
    .line 11
    const-string v3, "_iapx"

    .line 12
    .line 13
    const-string v4, "_exp_set"

    .line 14
    .line 15
    const-string v5, "_exp_clear"

    .line 16
    .line 17
    const-string v6, "_exp_activate"

    .line 18
    .line 19
    filled-new-array/range {v0 .. v8}, [Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sget v1, Lhr/k0;->f:I

    .line 24
    .line 25
    const/16 v1, 0xf

    .line 26
    .line 27
    new-array v2, v1, [Ljava/lang/Object;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    const-string v4, "_in"

    .line 31
    .line 32
    aput-object v4, v2, v3

    .line 33
    .line 34
    const/4 v4, 0x1

    .line 35
    const-string v5, "_xa"

    .line 36
    .line 37
    aput-object v5, v2, v4

    .line 38
    .line 39
    const/4 v4, 0x2

    .line 40
    const-string v5, "_xu"

    .line 41
    .line 42
    aput-object v5, v2, v4

    .line 43
    .line 44
    const/4 v4, 0x3

    .line 45
    const-string v5, "_aq"

    .line 46
    .line 47
    aput-object v5, v2, v4

    .line 48
    .line 49
    const/4 v5, 0x4

    .line 50
    const-string v6, "_aa"

    .line 51
    .line 52
    aput-object v6, v2, v5

    .line 53
    .line 54
    const/4 v6, 0x5

    .line 55
    const-string v7, "_ai"

    .line 56
    .line 57
    aput-object v7, v2, v6

    .line 58
    .line 59
    const/4 v6, 0x6

    .line 60
    const/16 v7, 0x9

    .line 61
    .line 62
    invoke-static {v0, v3, v2, v6, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 63
    .line 64
    .line 65
    invoke-static {v1, v2}, Lhr/k0;->o(I[Ljava/lang/Object;)Lhr/k0;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    sput-object v0, Lxr/a;->a:Lhr/k0;

    .line 70
    .line 71
    sget-object v0, Lhr/h0;->e:Lhr/f0;

    .line 72
    .line 73
    const-string v6, "_e"

    .line 74
    .line 75
    const-string v7, "_f"

    .line 76
    .line 77
    const-string v8, "_iap"

    .line 78
    .line 79
    const-string v9, "_s"

    .line 80
    .line 81
    const-string v10, "_au"

    .line 82
    .line 83
    const-string v11, "_ui"

    .line 84
    .line 85
    const-string v12, "_cd"

    .line 86
    .line 87
    filled-new-array/range {v6 .. v12}, [Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    const/4 v1, 0x7

    .line 92
    invoke-static {v1, v0}, Lhr/q;->a(I[Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    invoke-static {v1, v0}, Lhr/h0;->n(I[Ljava/lang/Object;)Lhr/x0;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    sput-object v0, Lxr/a;->b:Lhr/x0;

    .line 100
    .line 101
    const-string v0, "app"

    .line 102
    .line 103
    const-string v1, "am"

    .line 104
    .line 105
    const-string v2, "auto"

    .line 106
    .line 107
    filled-new-array {v2, v0, v1}, [Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-static {v4, v0}, Lhr/q;->a(I[Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    invoke-static {v4, v0}, Lhr/h0;->n(I[Ljava/lang/Object;)Lhr/x0;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    sput-object v0, Lxr/a;->c:Lhr/x0;

    .line 119
    .line 120
    const-string v0, "_r"

    .line 121
    .line 122
    const-string v1, "_dbg"

    .line 123
    .line 124
    invoke-static {v0, v1}, Lhr/h0;->v(Ljava/lang/Object;Ljava/lang/Object;)Lhr/x0;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    sput-object v0, Lxr/a;->d:Lhr/x0;

    .line 129
    .line 130
    new-instance v0, Lhr/e0;

    .line 131
    .line 132
    invoke-direct {v0, v5}, Lhr/b0;-><init>(I)V

    .line 133
    .line 134
    .line 135
    sget-object v1, Lvp/t1;->i:[Ljava/lang/String;

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Lhr/b0;->b([Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    sget-object v1, Lvp/t1;->j:[Ljava/lang/String;

    .line 141
    .line 142
    invoke-virtual {v0, v1}, Lhr/b0;->b([Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0}, Lhr/e0;->i()Lhr/x0;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    sput-object v0, Lxr/a;->e:Lhr/x0;

    .line 150
    .line 151
    const-string v0, "^_ltv_[A-Z]{3}$"

    .line 152
    .line 153
    const-string v1, "^_cc[1-5]{1}$"

    .line 154
    .line 155
    invoke-static {v0, v1}, Lhr/h0;->v(Ljava/lang/Object;Ljava/lang/Object;)Lhr/x0;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    sput-object v0, Lxr/a;->f:Lhr/x0;

    .line 160
    .line 161
    return-void
.end method

.method public static a(Ljava/lang/String;)Z
    .locals 1

    .line 1
    sget-object v0, Lxr/a;->c:Lhr/x0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lhr/h0;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public static b(Ljava/lang/String;Landroid/os/Bundle;)Z
    .locals 4

    .line 1
    sget-object v0, Lxr/a;->b:Lhr/x0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lhr/h0;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/4 v0, 0x0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    if-eqz p1, :cond_2

    .line 12
    .line 13
    sget-object p0, Lxr/a;->d:Lhr/x0;

    .line 14
    .line 15
    iget v1, p0, Lhr/x0;->g:I

    .line 16
    .line 17
    move v2, v0

    .line 18
    :cond_1
    if-ge v2, v1, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0, v2}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p1, v3}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    add-int/lit8 v2, v2, 0x1

    .line 31
    .line 32
    if-eqz v3, :cond_1

    .line 33
    .line 34
    :goto_0
    return v0

    .line 35
    :cond_2
    const/4 p0, 0x1

    .line 36
    return p0
.end method

.method public static c(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 4

    .line 1
    const-string v0, "_ce1"

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-string v1, "fcm"

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-nez v0, :cond_4

    .line 11
    .line 12
    const-string v0, "_ce2"

    .line 13
    .line 14
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const-string v0, "_ln"

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-nez p1, :cond_6

    .line 34
    .line 35
    const-string p1, "fiam"

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_5

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_1
    sget-object p0, Lxr/a;->e:Lhr/x0;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Lhr/h0;->contains(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    sget-object p0, Lxr/a;->f:Lhr/x0;

    .line 54
    .line 55
    iget v0, p0, Lhr/x0;->g:I

    .line 56
    .line 57
    move v1, v2

    .line 58
    :cond_3
    if-ge v1, v0, :cond_6

    .line 59
    .line 60
    invoke-virtual {p0, v1}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    check-cast v3, Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {p1, v3}, Ljava/lang/String;->matches(Ljava/lang/String;)Z

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    add-int/lit8 v1, v1, 0x1

    .line 71
    .line 72
    if-eqz v3, :cond_3

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    :goto_0
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    if-nez p1, :cond_6

    .line 80
    .line 81
    const-string p1, "frc"

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    if-eqz p0, :cond_5

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_5
    :goto_1
    return v2

    .line 91
    :cond_6
    :goto_2
    const/4 p0, 0x1

    .line 92
    return p0
.end method

.method public static d(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Z
    .locals 5

    .line 1
    const-string v0, "_cmp"

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x1

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    invoke-static {p0}, Lxr/a;->a(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    const/4 v1, 0x0

    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    if-nez p2, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    sget-object p1, Lxr/a;->d:Lhr/x0;

    .line 23
    .line 24
    iget v2, p1, Lhr/x0;->g:I

    .line 25
    .line 26
    move v3, v1

    .line 27
    :cond_3
    if-ge v3, v2, :cond_4

    .line 28
    .line 29
    invoke-virtual {p1, v3}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {p2, v4}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    add-int/lit8 v3, v3, 0x1

    .line 40
    .line 41
    if-eqz v4, :cond_3

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    const v2, 0x18b50

    .line 49
    .line 50
    .line 51
    const-string v3, "_cis"

    .line 52
    .line 53
    if-eq p1, v2, :cond_7

    .line 54
    .line 55
    const v2, 0x18b6e

    .line 56
    .line 57
    .line 58
    if-eq p1, v2, :cond_6

    .line 59
    .line 60
    const v2, 0x2ff42f

    .line 61
    .line 62
    .line 63
    if-eq p1, v2, :cond_5

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_5
    const-string p1, "fiam"

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_8

    .line 73
    .line 74
    const-string p0, "fiam_integration"

    .line 75
    .line 76
    invoke-virtual {p2, v3, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return v0

    .line 80
    :cond_6
    const-string p1, "fdl"

    .line 81
    .line 82
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-eqz p0, :cond_8

    .line 87
    .line 88
    const-string p0, "fdl_integration"

    .line 89
    .line 90
    invoke-virtual {p2, v3, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    return v0

    .line 94
    :cond_7
    const-string p1, "fcm"

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-eqz p0, :cond_8

    .line 101
    .line 102
    const-string p0, "fcm_integration"

    .line 103
    .line 104
    invoke-virtual {p2, v3, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    return v0

    .line 108
    :cond_8
    :goto_0
    return v1
.end method
