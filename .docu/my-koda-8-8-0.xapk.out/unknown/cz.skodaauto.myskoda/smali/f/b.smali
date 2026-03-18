.class public final Lf/b;
.super Lf/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lf/b;->a:I

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    if-le p1, p0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 11
    .line 12
    const-string p1, "Max items must be higher than 1"

    .line 13
    .line 14
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method


# virtual methods
.method public final a(Landroid/content/Context;Ljava/lang/Object;)Landroid/content/Intent;
    .locals 4

    .line 1
    check-cast p2, Le/k;

    .line 2
    .line 3
    const-string v0, "input"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v1, 0x21

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    iget p0, p0, Lf/b;->a:I

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    if-lt v0, v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/16 v1, 0x1e

    .line 20
    .line 21
    if-lt v0, v1, :cond_2

    .line 22
    .line 23
    invoke-static {}, Ld6/t1;->D()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v1, 0x2

    .line 28
    if-lt v0, v1, :cond_2

    .line 29
    .line 30
    :goto_0
    new-instance p1, Landroid/content/Intent;

    .line 31
    .line 32
    const-string v0, "android.provider.action.PICK_IMAGES"

    .line 33
    .line 34
    invoke-direct {p1, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p2, Le/k;->a:Lf/f;

    .line 38
    .line 39
    invoke-static {v0}, Lkp/x6;->c(Lf/f;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p1, v0}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 44
    .line 45
    .line 46
    iget v0, p2, Le/k;->b:I

    .line 47
    .line 48
    invoke-static {p0, v0}, Ljava/lang/Math;->min(II)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-le p0, v3, :cond_1

    .line 53
    .line 54
    invoke-static {}, Lb/s;->a()I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-gt p0, v0, :cond_1

    .line 59
    .line 60
    const-string v0, "android.provider.extra.PICK_IMAGES_MAX"

    .line 61
    .line 62
    invoke-virtual {p1, v0, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 63
    .line 64
    .line 65
    iget-object p0, p2, Le/k;->c:Lf/c;

    .line 66
    .line 67
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    const-string p0, "android.provider.extra.PICK_IMAGES_LAUNCH_TAB"

    .line 71
    .line 72
    invoke-virtual {p1, p0, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 73
    .line 74
    .line 75
    const-string p0, "android.provider.extra.PICK_IMAGES_IN_ORDER"

    .line 76
    .line 77
    invoke-virtual {p1, p0, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 78
    .line 79
    .line 80
    return-object p1

    .line 81
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 82
    .line 83
    const-string p1, "Max items must be greater than 1 and lesser than or equal to MediaStore.getPickImagesMaxLimit()"

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_2
    invoke-static {p1}, Lkp/x6;->b(Landroid/content/Context;)Landroid/content/pm/ResolveInfo;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    if-eqz v0, :cond_5

    .line 94
    .line 95
    invoke-static {p1}, Lkp/x6;->b(Landroid/content/Context;)Landroid/content/pm/ResolveInfo;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    if-eqz p1, :cond_4

    .line 100
    .line 101
    iget-object p1, p1, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 102
    .line 103
    new-instance v0, Landroid/content/Intent;

    .line 104
    .line 105
    const-string v1, "androidx.activity.result.contract.action.PICK_IMAGES"

    .line 106
    .line 107
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget-object v1, p1, Landroid/content/pm/ActivityInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 111
    .line 112
    iget-object v1, v1, Landroid/content/pm/ApplicationInfo;->packageName:Ljava/lang/String;

    .line 113
    .line 114
    iget-object p1, p1, Landroid/content/pm/ActivityInfo;->name:Ljava/lang/String;

    .line 115
    .line 116
    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 117
    .line 118
    .line 119
    iget-object p1, p2, Le/k;->a:Lf/f;

    .line 120
    .line 121
    invoke-static {p1}, Lkp/x6;->c(Lf/f;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {v0, p1}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 126
    .line 127
    .line 128
    iget p1, p2, Le/k;->b:I

    .line 129
    .line 130
    invoke-static {p0, p1}, Ljava/lang/Math;->min(II)I

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-le p0, v3, :cond_3

    .line 135
    .line 136
    const-string p1, "androidx.activity.result.contract.extra.PICK_IMAGES_MAX"

    .line 137
    .line 138
    invoke-virtual {v0, p1, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 139
    .line 140
    .line 141
    iget-object p0, p2, Le/k;->c:Lf/c;

    .line 142
    .line 143
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    const-string p0, "androidx.activity.result.contract.extra.PICK_IMAGES_LAUNCH_TAB"

    .line 147
    .line 148
    invoke-virtual {v0, p0, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 149
    .line 150
    .line 151
    const-string p0, "androidx.activity.result.contract.extra.PICK_IMAGES_IN_ORDER"

    .line 152
    .line 153
    invoke-virtual {v0, p0, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 154
    .line 155
    .line 156
    return-object v0

    .line 157
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 158
    .line 159
    const-string p1, "Max items must be greater than 1"

    .line 160
    .line 161
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw p0

    .line 165
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 166
    .line 167
    const-string p1, "Required value was null."

    .line 168
    .line 169
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :cond_5
    new-instance p0, Landroid/content/Intent;

    .line 174
    .line 175
    const-string p1, "android.intent.action.OPEN_DOCUMENT"

    .line 176
    .line 177
    invoke-direct {p0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    iget-object p1, p2, Le/k;->a:Lf/f;

    .line 181
    .line 182
    invoke-static {p1}, Lkp/x6;->c(Lf/f;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    invoke-virtual {p0, p1}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 187
    .line 188
    .line 189
    const-string p1, "android.intent.extra.ALLOW_MULTIPLE"

    .line 190
    .line 191
    invoke-virtual {p0, p1, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 192
    .line 193
    .line 194
    invoke-virtual {p0}, Landroid/content/Intent;->getType()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    if-nez p1, :cond_6

    .line 199
    .line 200
    const-string p1, "*/*"

    .line 201
    .line 202
    invoke-virtual {p0, p1}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 203
    .line 204
    .line 205
    const-string p1, "image/*"

    .line 206
    .line 207
    const-string p2, "video/*"

    .line 208
    .line 209
    filled-new-array {p1, p2}, [Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    const-string p2, "android.intent.extra.MIME_TYPES"

    .line 214
    .line 215
    invoke-virtual {p0, p2, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[Ljava/lang/String;)Landroid/content/Intent;

    .line 216
    .line 217
    .line 218
    :cond_6
    return-object p0
.end method

.method public final b(Landroid/content/Context;Ljava/lang/Object;)Lbu/c;
    .locals 0

    .line 1
    check-cast p2, Le/k;

    .line 2
    .line 3
    const-string p0, "input"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method

.method public final c(Landroid/content/Intent;I)Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 p0, -0x1

    .line 2
    if-ne p2, p0, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 p1, 0x0

    .line 6
    :goto_0
    if-eqz p1, :cond_5

    .line 7
    .line 8
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    if-eqz p2, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, p2}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    :cond_1
    invoke-virtual {p1}, Landroid/content/Intent;->getClipData()Landroid/content/ClipData;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    if-nez p1, :cond_2

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    if-eqz p2, :cond_2

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_2
    if-eqz p1, :cond_4

    .line 36
    .line 37
    invoke-virtual {p1}, Landroid/content/ClipData;->getItemCount()I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    const/4 v0, 0x0

    .line 42
    :goto_1
    if-ge v0, p2, :cond_4

    .line 43
    .line 44
    invoke-virtual {p1, v0}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {v1}, Landroid/content/ClipData$Item;->getUri()Landroid/net/Uri;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    invoke-virtual {p0, v1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    :cond_3
    add-int/lit8 v0, v0, 0x1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_4
    new-instance p1, Ljava/util/ArrayList;

    .line 61
    .line 62
    invoke-direct {p1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 63
    .line 64
    .line 65
    return-object p1

    .line 66
    :cond_5
    :goto_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 67
    .line 68
    return-object p0
.end method
